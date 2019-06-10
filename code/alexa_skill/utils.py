def run_workers(operation):
    """
    Runs a function
    """
    function_name = operation[0]
    parameters = operation[1]
    return function_name(**parameters)
