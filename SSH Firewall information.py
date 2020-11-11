"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'list_firewall_rules_1' block
    list_firewall_rules_1(container=container)

    return

def list_firewall_rules_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_firewall_rules_1() called')

    # collect data for 'list_firewall_rules_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceHostName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_firewall_rules_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'port': "",
                'chain': "INPUT",
                'protocol': "",
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list firewall rules", parameters=parameters, assets=['ssh'], callback=Summery_of_the_firewall_information, name="list_firewall_rules_1")

    return

def Summery_of_the_firewall_information(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summery_of_the_firewall_information() called')
    
    template = """{0}

{1}"""

    # parameter list for template variable replacement
    parameters = [
        "list_firewall_rules_1:action_result.message",
        "list_firewall_rules_1:action_result.summary",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summery_of_the_firewall_information")

    add_note_1(container=container)

    return

def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_1() called')

    formatted_data_1 = phantom.get_format_data(name='Summery_of_the_firewall_information')

    note_title = "Firewall iinformation"
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