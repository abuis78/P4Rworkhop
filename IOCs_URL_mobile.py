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
            ["URL Artifact", "==", "artifact:*.name"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        unshorten_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["URL_reputation:action_result.data.*.positives", ">", 0],
            ["URL_reputation:action_result.data.*.positives", "<", 5],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["URL_reputation:action_result.data.*.positives", ">=", 5],
            ["URL_reputation:action_result.data.*.positives", "<", 15],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["URL_reputation:action_result.data.*.positives", ">=", 15],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def Text_high_HUD(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_high_HUD() called')
    
    template = """Positive Results: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "URL_reputation:action_result.data.*.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_high_HUD")

    Text_URL(container=container)

    return

def Add_HUD_high_red(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_HUD_high_red() called')

    formatted_data_1 = phantom.get_format_data(name='Text_high_HUD')
    formatted_data_2 = phantom.get_format_data(name='Text_URL')

    phantom.pin(container=container, data=formatted_data_1, message=formatted_data_2, name=None)

    phantom.add_tags(container=container, tags="suspicious")
    get_screenshot_2(container=container)

    return

def Text_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_URL() called')
    
    template = """URL Reputation {0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_URL")

    Add_HUD_high_red(container=container)

    return

def URL_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URL_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'URL_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['unshorten_url_1:action_result.data.*.unshortened_url', 'unshorten_url_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'URL_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=URL_reputation_callback, name="URL_reputation")

    return

def URL_reputation_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('URL_reputation_callback() called')
    
    decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Save_Data_in_Object(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['unshorten_url_1:action_result.data.*.unshortened_url', 'unshorten_url_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                'size': "Normal",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshot machine'], name="get_screenshot_1")

    return

def unshorten_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unshorten_url_1() called')

    # collect data for 'unshorten_url_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'unshorten_url_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="unshorten url", parameters=parameters, assets=['phantom utilities'], callback=decision_3, name="unshorten_url_1")

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Unable to unshorten url", "in", "unshorten_url_1:action_result.status"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Text_Unable_to_unshorten_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    URL_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Text_Unable_to_unshorten_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_Unable_to_unshorten_url() called')
    
    template = """Phantom was not able to unshorten the URL:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_Unable_to_unshorten_url")

    add_note_5(container=container)

    return

def add_note_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_5() called')

    formatted_data_1 = phantom.get_format_data(name='Text_Unable_to_unshorten_url')

    note_title = "URL NOT unshortend"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.requestURL", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        high_greater_than_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def high_greater_than_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('high_greater_than_15() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'high_greater_than_15' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.id', 'filtered-data:filter_3:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'high_greater_than_15' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"high\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], callback=Text_high_HUD, name="high_greater_than_15")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.requestURL", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        low_0_to_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def low_0_to_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('low_0_to_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'low_0_to_5' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:artifact:*.id', 'filtered-data:filter_4:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'low_0_to_5' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"low\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="low_0_to_5")

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.requestURL", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.requestURL"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        medium_5_to_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def medium_5_to_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('medium_5_to_15() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'medium_5_to_15' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.id', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'medium_5_to_15' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"medium\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], callback=Add_tag_suspicious, name="medium_5_to_15")

    return

def Add_tag_suspicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_tag_suspicious() called')

    phantom.add_tags(container=container, tags="suspicious")
    get_screenshot_1(container=container)

    return

def get_screenshot_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_2' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['high_greater_than_15:artifact:*.cef.requestURL', 'high_greater_than_15:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_screenshot_2' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'url': inputs_item_1[0],
                'size': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshot machine'], name="get_screenshot_2")

    return

def Save_Data_in_Object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Save_Data_in_Object() called')
    
    id_value = container.get('id', None)
    results_data_1 = phantom.collect2(container=container, datapath=['URL_reputation:action_result.message'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    container_id = container['id']

    phantom.save_object(key="IOCs_URL", value={'value': results_data_1}, auto_delete=True,container_id = container_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

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