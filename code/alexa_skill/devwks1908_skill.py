import logging
from multiprocessing.dummy import Pool
import sys
import re
import six

from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.dispatch_components import AbstractExceptionHandler
from ask_sdk_core.utils import is_request_type, is_intent_name
from ask_sdk_core.handler_input import HandlerInput

from ask_sdk_model.ui import SimpleCard
from ask_sdk_model import Response, IntentConfirmationStatus
from ask_sdk_model.slu.entityresolution import StatusCode

from dnac import *
from aci import *
import utils

skill_name = 'Robot'
sb = SkillBuilder()

logger = setup_logging()
logger.setLevel(logging.INFO)
thread_timeout = 8640

dnac_api = Dnac(DNAC_HOST, DNAC_PORT, DNAC_USER, DNAC_PASSWORD)
aci_api = Aci(APIC_HOST, APIC_PORT, APIC_USER, APIC_PASSWORD)


def get_slot_values(filled_slots):
    """Return slot values with additional info."""
    # type: (Dict[str, Slot]) -> Dict[str, Any]
    slot_values = {}

    for key, slot_item in six.iteritems(filled_slots):
        name = slot_item.name
        try:
            status_code = slot_item.resolutions.resolutions_per_authority[0].status.code

            if status_code == StatusCode.ER_SUCCESS_MATCH:
                slot_values[name] = {
                    "synonym": slot_item.value,
                    "resolved": slot_item.resolutions.resolutions_per_authority[0].values[0].value.name,
                    "id": slot_item.resolutions.resolutions_per_authority[0].values[0].value.id,
                    "is_validated": True,
                }
            elif status_code == StatusCode.ER_SUCCESS_NO_MATCH:
                slot_values[name] = {
                    "synonym": slot_item.value,
                    "resolved": slot_item.value,
                    "is_validated": False,
                }
            else:
                pass
        except (AttributeError, ValueError, KeyError, IndexError, TypeError) as e:
            logger.info("Couldn't resolve status_code for slot item: {}".format(slot_item))
            logger.info(e)
            slot_values[name] = {
                "synonym": slot_item.value,
                "resolved": slot_item.value,
                "is_validated": False,
            }
    return slot_values


class GetServerLocationIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("GetServerLocationIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        slots = handler_input.request_envelope.request.intent.slots
        print(get_slot_values(slots))
        server_id = get_slot_values(slots)['server_name'].get('id')
        server_name = get_slot_values(slots)['server_name'].get('resolved')
        logger.info('Server name: {}, Server ID: {}'.format(server_name, server_id))

        endpoint_details = aci_api.get_ep_details(server_id)
        if not endpoint_details:
            speech_text = 'No server called {} was found by Cisco Robot.'.format(server_name)
        else:
            vlan = endpoint_details.get('vlan')
            ip = endpoint_details.get('ip')
            speech_text = 'An endpoint called {} was found. It is provisioned in VLAN {}'.format(server_name, vlan)
            if ip:
                speech_text += ', with the IP address {}.'.format(ip)

            speech_text += ' It is connected to '

            for i, location in enumerate(endpoint_details.get('locations')):
                if i > 0:
                    speech_text += ' and '
                node = location.get('node')
                ports = location.get('ports')
                speech_text += 'leaf switch {}, '.format(node)
                for j, port in enumerate(ports):
                    if j > 0:
                        speech_text += ' and '
                    speech_text += 'port {}/{}, '.format(port.get('card'), port.get('port'))

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class DeleteSegmentIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("DeleteSegmentIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        confirmation_status = handler_input.request_envelope.request.intent.confirmation_status
        logger.info('Intent confirmation = {}'.format(confirmation_status))
        if confirmation_status != IntentConfirmationStatus.CONFIRMED:
            speech_text = 'Alright, the operation was cancelled.'
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        slots = handler_input.request_envelope.request.intent.slots
        segment_name = slots.get('segment').value.replace(' ', '').capitalize()
        logger.info('Segment name: {}'.format(segment_name))

        if not re.match('^[0-9A-Za-z_]{1,16}$', segment_name):
            logger.error('Bad segment name: {}'.format(segment_name))
            speech_text = ('{} was not accepted. Segment name can be up to 16 alphanumeric '
                           'characters'.format(segment_name))
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        # Make multiple API requests in parallel using multi-threading
        pool = Pool(processes=4)
        operations = []
        operations.append((dnac_api.exists_virtual_network, {'vn_name': segment_name}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        if not data[0]:
            speech_text = 'There is no segment called {}.'.format(segment_name)
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        pool = Pool(processes=4)
        operations = []
        operations.append((dnac_api.delete_virtual_network_by_name, {'vn_name': segment_name, 'asynch': False}))
        operations.append((aci_api.delete_tenant, {'tenant_name': segment_name}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        if not data or len(data) < 2:
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            dnac_response = data[0]
            apic_response = data[1]
            if dnac_response.get('isError') or not apic_response.ok:
                speech_text = ('There was an error deleting the segment. Please check the SDN controllers logs '
                               'for more information.')
            else:
                speech_text = 'The segment {} was successfully deleted by Cisco Robot.'.format(segment_name)

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class CreateSegmentIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("CreateSegmentIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        slots = handler_input.request_envelope.request.intent.slots
        segment_name = slots.get('segment').value.replace(' ', '').capitalize()
        logger.info('New segment name: {}'.format(segment_name))

        if not re.match('^[0-9A-Za-z]{1,16}$', segment_name):
            logger.error('Bad segment name: {}'.format(segment_name))
            speech_text = ('{} was not accepted. Segment name can be up to 16 alphanumeric '
                           'characters'.format(segment_name))
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        # Make multiple API requests in parallel using multi-threading
        pool = Pool(processes=4)
        operations = []
        operations.append((dnac_api.exists_virtual_network, {'vn_name': segment_name}))
        operations.append((aci_api.exists_tenant, {'tenant_name': segment_name}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        if not data or len(data) < 2:
            logger.error('Incomplete or no data received from SDN controllers. Received data: {}'.format(data))
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            dnac_response = data[0]
            apic_response = data[1]

        segment_exists = dnac_response or apic_response

        if segment_exists:
            logger.warning('The segment already exists in at least one controller. Received data: {}'.format(data))
            speech_text = 'Sorry, the segment {} already exists. Please choose a different segment name.'.format(
                segment_name)
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        payload = [
            {
                "name": segment_name,
                "virtualNetworkContextType": "ISOLATED"
            }
        ]

        pool = Pool(processes=4)
        operations = []
        operations.append((dnac_api.create_virtual_network, {'payload': payload, 'asynch': False}))
        operations.append((aci_api.create_tenant, {'tenant_name': segment_name, 'vrf_name': segment_name + '-VRF'}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        if not data or len(data) < 2:
            logger.error('Incomplete or no data received from SDN controllers. Received data: {}'.format(data))
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            dnac_response = data[0]
            apic_response = data[1]
            if dnac_response.get('isError') or not apic_response.ok:
                speech_text = ('There was an error creating the segment. Please check the SDN controllers logs '
                               'for more information.')
            else:
                speech_text = 'The segment {} was successfully created by Cisco Robot.'.format(segment_name)

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class AllowToTalkIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AllowToTalkIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        # Make multiple API requests in parallel using multi-threading
        pool = Pool(processes=2)
        operations = []
        operations.append((aci_api.toggle_provide_contract, {'provide': True}))
        operations.append((aci_api.toggle_consume_contract, {'consume': True}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        speech_text = 'Light bulbs can now talk to smart controllers.'

        if not data or len(data) < 2:
            logger.error('Incomplete or no data received from SDN controllers. Received data: {}'.format(data))
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            provide_contract_response = data[0]
            consume_contract_response = data[1]

            logger.info('Provide Contract response: {}'.format(provide_contract_response.text))
            logger.info('Consume Contract response: {}'.format(consume_contract_response.text))

            if 'already exists' in provide_contract_response.text + consume_contract_response.text:
                logger.warning('The contract was already provided or consumed.')
            elif provide_contract_response.status_code != 200 or consume_contract_response.status_code != 200:
                logger.warning('The operation failed.')
                speech_text = 'Sorry, the operation has failed.'

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class DenyToTalkIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("DenyToTalkIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        confirmation_status = handler_input.request_envelope.request.intent.confirmation_status
        logger.info('Intent confirmation = {}'.format(confirmation_status))
        if confirmation_status != IntentConfirmationStatus.CONFIRMED:
            speech_text = 'Alright, the operation was cancelled.'
            handler_input.response_builder.speak(speech_text).set_card(
                SimpleCard(skill_name, speech_text)).set_should_end_session(False)
            return handler_input.response_builder.response

        # Make multiple API requests in parallel using multi-threading
        pool = Pool(processes=2)
        operations = []
        operations.append((aci_api.toggle_provide_contract, {'provide': False}))
        operations.append((aci_api.toggle_consume_contract, {'consume': False}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        speech_text = 'From this moment, light bulbs cannot talk to smart controllers.'

        if not data or len(data) < 2:
            logger.error('Incomplete or no data received from SDN controllers. Received data: {}'.format(data))
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            provide_contract_response = data[0]
            consume_contract_response = data[1]

            logger.info('Provide Contract response: {}'.format(provide_contract_response.text))
            logger.info('Consume Contract response: {}'.format(consume_contract_response.text))

            if provide_contract_response.status_code != 200 or consume_contract_response.status_code != 200:
                logger.warning('The operation failed.')
                speech_text = 'Sorry, the operation has failed.'

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class GetNetworkHealthIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("GetNetworkHealthIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response

        # Make multiple API requests in parallel using multi-threading
        pool = Pool(processes=4)
        operations = []
        operations.append((dnac_api.get_current_network_health, {}))
        operations.append((aci_api.get_fabric_health, {}))
        data = pool.map_async(utils.run_workers, operations).get(thread_timeout)
        pool.close()
        pool.join()

        if not data or len(data) < 2:
            logger.error('Incomplete or no data received from SDN controllers. Received data: {}'.format(data))
            speech_text = 'Unable to get response from SDN controllers.'
        else:
            dnac_health = data[0][0].get('healthScore')
            aci_health = data[1].json()['imdata'][0]['fabricOverallHealthHist5min']['attributes'].get('healthAvg')

            speech_text = ('The SDA network health index is {} percent, and the DC Fabric health '
                           'index is {} percent.'.format(dnac_health, aci_health))

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(False)
        return handler_input.response_builder.response


class LaunchRequestHandler(AbstractRequestHandler):
    """Handler for Skill Launch."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_request_type("LaunchRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = ("Welcome to {}.".format(skill_name))

        if dnac_api.token and aci_api.cookie:
            speech_text += ' The connection to the Cisco SDN controllers was successfully established.'
            should_end_session = False
        elif dnac_api.token and not aci_api.cookie:
            speech_text += ' Sorry, I was unable to connect to Cisco ACI controller.'
            should_end_session = True
        elif not dnac_api.token and aci_api.cookie:
            speech_text += ' Sorry, I was unable to connect to Cisco DNA Center controller.'
            should_end_session = True
        else:
            speech_text += ' Sorry, I was unable to connect to Cisco DNA Center and to Cisco ACI controllers.'
            should_end_session = True

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text)).set_should_end_session(should_end_session)
        return handler_input.response_builder.response


class HelpIntentHandler(AbstractRequestHandler):
    """Handler for Help Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "You can say hello to me!"

        handler_input.response_builder.speak(speech_text).ask(
            speech_text).set_card(SimpleCard(
            skill_name, speech_text))
        return handler_input.response_builder.response


class CancelOrStopIntentHandler(AbstractRequestHandler):
    """Single handler for Cancel and Stop Intent."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return (is_intent_name("AMAZON.CancelIntent")(handler_input) or
                is_intent_name("AMAZON.StopIntent")(handler_input))

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "Thanks for using {} skill. Goodbye!".format(skill_name)

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard(skill_name, speech_text))
        return handler_input.response_builder.response


class FallbackIntentHandler(AbstractRequestHandler):
    """AMAZON.FallbackIntent is only available in en-US locale.
    This handler will not be triggered except in that locale,
    so it is safe to deploy on any locale.
    """

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AMAZON.FallbackIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = (
            "The {} skill can't help you with that.  "
            "You can ask me things like: Create a new segment").format(skill_name)
        reprompt = "You can say hello!!"
        handler_input.response_builder.speak(speech_text).ask(reprompt)
        return handler_input.response_builder.response


class SessionEndedRequestHandler(AbstractRequestHandler):
    """Handler for Session End."""

    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "Thanks for using {} skill. Goodbye!".format(skill_name)
        handler_input.response_builder.speak(speech_text)
        return handler_input.response_builder.response


class CatchAllExceptionHandler(AbstractExceptionHandler):
    """Catch all exception handler, log exception and
    respond with custom message.
    """

    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        logger.error(exception, exc_info=True)

        speech = "Sorry, there was some problem. Please try again!!"
        handler_input.response_builder.speak(speech).ask(speech)

        return handler_input.response_builder.response


sb.add_request_handler(LaunchRequestHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(FallbackIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())
sb.add_request_handler(CreateSegmentIntentHandler())
sb.add_request_handler(DeleteSegmentIntentHandler())
sb.add_request_handler(GetNetworkHealthIntentHandler())
sb.add_request_handler(AllowToTalkIntentHandler())
sb.add_request_handler(DenyToTalkIntentHandler())
sb.add_request_handler(GetServerLocationIntentHandler())

sb.add_exception_handler(CatchAllExceptionHandler())

handler = sb.lambda_handler()
