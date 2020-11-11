"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Capture_object' block
    Capture_object(container=container)

    return

def Capture_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Capture_object() called')
    
    id_value = container.get('id', None)

    Capture_object__file = None
    Capture_object__ip = None
    Capture_object__domain = None
    Capture_object__url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    container_id = container['id']
    
    Capture_object__file = phantom.get_object(key='Check_File_reputation',container_id = container_id)
    Capture_object__file = Capture_object__file[0]['value']['feedback']
    
    Capture_object__ip = phantom.get_object(key='Check_IP_reputation',container_id = container_id)
    Capture_object__ip = Capture_object__ip[0]['value']['feedback']
    
    Capture_object__domain = phantom.get_object(key='Check_Domain_reputation',container_id = container_id)
    Capture_object__domain = Capture_object__domain[0]['value']['feedback']
    
    Capture_object__url = phantom.get_object(key='Check_URL_reputation',container_id = container_id)
    Capture_object__url = Capture_object__url[0]['value']['feedback']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Capture_object:file', value=json.dumps(Capture_object__file))
    phantom.save_run_data(key='Capture_object:ip', value=json.dumps(Capture_object__ip))
    phantom.save_run_data(key='Capture_object:domain', value=json.dumps(Capture_object__domain))
    phantom.save_run_data(key='Capture_object:url', value=json.dumps(Capture_object__url))
    Format_the_summarized_information(container=container)

    return

def Format_the_summarized_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_the_summarized_information() called')
    
    template = """{0}
------------
{1}
------------
{2}
------------
{3}"""

    # parameter list for template variable replacement
    parameters = [
        "Capture_object:custom_function:file",
        "Capture_object:custom_function:ip",
        "Capture_object:custom_function:domain",
        "Capture_object:custom_function:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_the_summarized_information")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return