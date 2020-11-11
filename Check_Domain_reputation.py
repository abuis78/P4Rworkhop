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
            ["Domain Artifact", "==", "artifact:*.name"],
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
            ["filtered-data:filter_1:condition_1:artifact:*.cef.destinationDnsDomain", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'domain': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=domain_reputation_1_callback, name="domain_reputation_1")

    return

def domain_reputation_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('domain_reputation_1_callback() called')
    
    filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    Summery_Domain_Reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def low_greater_than_0_to_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('low_greater_than_0_to_5() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'low_greater_than_0_to_5' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_6:condition_1:artifact:*.id', 'filtered-data:filter_6:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'low_greater_than_0_to_5' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"low\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="low_greater_than_0_to_5")

    return

def medium_5_to_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('medium_5_to_15() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'medium_5_to_15' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_7:condition_1:artifact:*.id', 'filtered-data:filter_7:condition_1:artifact:*.id'])

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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="medium_5_to_15")

    return

def No_results_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('No_results_0() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'No_results_0' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.id', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'No_results_0' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"No results\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="No_results_0")

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.summary.detected_urls", ">", 0],
            ["domain_reputation_1:action_result.summary.detected_urls", "<", 5],
        ],
        logical_operator='and',
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.summary.detected_urls", ">=", 5],
            ["domain_reputation_1:action_result.summary.detected_urls", "<", 15],
        ],
        logical_operator='and',
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.summary.detected_urls", ">=", 15],
        ],
        name="filter_3:condition_3")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        filter_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    # collect filtered artifact ids for 'if' condition 4
    matched_artifacts_4, matched_results_4 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.summary.detected_urls", "==", 0],
        ],
        name="filter_3:condition_4")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_4 or matched_results_4:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_4, filtered_results=matched_results_4)

    # collect filtered artifact ids for 'if' condition 5
    matched_artifacts_5, matched_results_5 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Exceeded API request rate limit.", "in", "domain_reputation_1:action_result.message"],
        ],
        name="filter_3:condition_5")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_5 or matched_results_5:
        filter_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_5, filtered_results=matched_results_5)

    return

def high_greater_than_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('high_greater_than_15() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'high_greater_than_15' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_4:condition_1:artifact:*.id', 'filtered-data:filter_4:condition_1:artifact:*.id'])

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

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], callback=Text_Domain, name="high_greater_than_15")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_3:domain_reputation_1:action_result.parameter.domain", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        high_greater_than_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_4:domain_reputation_1:action_result.parameter.domain", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        No_results_0(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_1:domain_reputation_1:action_result.parameter.domain", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        low_greater_than_0_to_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_2:domain_reputation_1:action_result.parameter.domain", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        medium_5_to_15(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_3:condition_5:domain_reputation_1:action_result.parameter.domain", "==", "filtered-data:filter_2:condition_1:artifact:*.cef.destinationDnsDomain"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Exceeded_API_request(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Exceeded_API_request(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Exceeded_API_request() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Exceeded_API_request' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_8:condition_1:artifact:*.id', 'filtered-data:filter_8:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Exceeded_API_request' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'data': "{\"severity\":\"Api limit exceeded\",\"label\":\"artifact\"}",
            'overwrite': True,
            'artifact_id': filtered_artifacts_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="Exceeded_API_request")

    return

def Text_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Text_Domain() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_4:condition_1:artifact:*.cef.destinationDnsDomain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Text_Domain")

    HUD_header(container=container)

    return

def HUD_header(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('HUD_header() called')
    
    template = """This are the Domains with a detection rate > 15"""

    # parameter list for template variable replacement
    parameters = [
        "high_greater_than_15:artifact:*.cef.destinationDnsDomain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="HUD_header")

    pin_1(container=container)

    return

def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_1() called')

    formatted_data_1 = phantom.get_format_data(name='Text_Domain')
    formatted_data_2 = phantom.get_format_data(name='HUD_header')

    phantom.pin(container=container, data=formatted_data_1, message=formatted_data_2, pin_type="card", pin_style="red", name=None)

    return

def Summery_Domain_Reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summery_Domain_Reputation() called')
    
    template = """Domain check
Domain: {1}
Result:  {0}"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_1:action_result.message",
        "domain_reputation_1:action_result.parameter.domain",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summery_Domain_Reputation")

    Summer_save_object(container=container)

    return

def Summer_save_object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summer_save_object() called')
    
    id_value = container.get('id', None)
    formatted_data_1 = phantom.get_format_data(name='Summery_Domain_Reputation')

    Summer_save_object__output_playbook = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    container_id = container['id']
    pb_info = phantom.get_playbook_info()
    playbook_name = pb_info[0].get('name', None)
    phantom.save_object(key=playbook_name, value={ 'feedback' : formatted_data_1 }, auto_delete=True,container_id = container_id)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Summer_save_object:output_playbook', value=json.dumps(Summer_save_object__output_playbook))

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