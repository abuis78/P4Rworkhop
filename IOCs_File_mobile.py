"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Vault Artifact", "in", "artifact:*.name"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_4:action_result.summary.positives", ">", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Score(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def pin_add_tag_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_add_tag_1() called')

    formatted_data_1 = phantom.get_format_data(name='Summary')

    phantom.pin(container=container, data=formatted_data_1, message="Result of file reputation", pin_type="card", pin_style="red", name=None)

    phantom.add_tags(container=container, tags="suspicious")
    Save_result_in_object(container=container)

    return

def Text_file_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_file_name() called')
    
    template = """File Reputation {0}  ({1}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.fileName",
        "Score:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_file_name")

    join_Summary(container=container)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.fileName", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Text_file_name(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Text_IF_no_file_name(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Score() called')
    
    template = """- {0}"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_4:action_result.summary.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Score")

    decision_4(container=container)

    return

def Text_IF_no_file_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_IF_no_file_name() called')
    
    template = """The file attachment should be considered suspicious"""

    # parameter list for template variable replacement
    parameters = [
        "Score:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_IF_no_file_name")

    join_Summary(container=container)

    return

def Summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summary() called')
    
    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "Text_file_name:formatted_data",
        "Text_IF_no_file_name:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summary")

    pin_add_tag_1(container=container)

    return

def join_Summary(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Summary() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['file_reputation_4']):
        
        # call connected block "Summary"
        Summary(container=container, handle=handle)
    
    return

def file_reputation_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_4() called')

    # collect data for 'file_reputation_4' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_4' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="file_reputation_4")

    return

def Save_result_in_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Save_result_in_object() called')
    
    id_value = container.get('id', None)
    formatted_data_1 = phantom.get_format_data(name='Summary')

    Save_result_in_object__save_object_output = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    container_id = container['id']

    phantom.save_object(key="key1", value={'value': formatted_data_1}, auto_delete=True,container_id = container_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Save_result_in_object:save_object_output', value=json.dumps(Save_result_in_object__save_object_output))

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