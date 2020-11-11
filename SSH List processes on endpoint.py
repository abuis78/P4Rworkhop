"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'list_processes_1' block
    list_processes_1(container=container)

    return

def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_processes_1() called')

    # collect data for 'list_processes_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceHostName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_processes_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list processes", parameters=parameters, assets=['ssh'], callback=format_1, name="list_processes_1")

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_1() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "list_processes_1:action_result.summary",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_note_1(container=container)

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    formatted_data_1 = phantom.get_format_data(name='format_1')

    note_title = "List process result"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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