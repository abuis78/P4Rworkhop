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
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        VT_URL_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def VT_URL_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VT_URL_reputation() called')

    # collect data for 'VT_URL_reputation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'VT_URL_reputation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal demo'], callback=filter_2, name="VT_URL_reputation")

    return

def URLSCANIO_url_detonation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('URLSCANIO_url_detonation() called')

    # collect data for 'URLSCANIO_url_detonation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'URLSCANIO_url_detonation' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'private': False,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="detonate url", parameters=parameters, assets=['urlscan'], callback=filter_4, name="URLSCANIO_url_detonation")

    return

def get_screenshot_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_1() called')

    # collect data for 'get_screenshot_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.requestURL', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_screenshot_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'url': filtered_artifacts_item_1[0],
                'size': "Medium",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshotmachine_dummy'], callback=filter_6, name="get_screenshot_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["VT_URL_reputation:action_result.parameter.context.artifact_id", "==", "filtered-data:filter_1:condition_1:artifact:*.id"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_2:condition_1:artifact:*.id", "==", "VT_URL_reputation:action_result.parameter.context.artifact_id"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        vt_if_no_output(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def vt_if_no_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('vt_if_no_output() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:VT_URL_reputation:action_result.data.*.positives'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    vt_if_no_output__vt_result = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    vt_if_no_output__vt_result = [ i if i is not None else 'no results' for i in filtered_results_item_1_0]    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='vt_if_no_output:vt_result', value=json.dumps(vt_if_no_output__vt_result))
    vt_update(container=container)

    return

def vt_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('vt_update() called')
    
    template = """%%
{{ \"cef\":{{ \"VT_URL_positives\": \"{0}\", \"VT_URL_messages\": \"{1}\" }} }}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "vt_if_no_output:custom_function:vt_result",
        "filtered-data:filter_3:condition_1:VT_URL_reputation:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="vt_update")

    add_vt_results_to_artifact(container=container)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["URLSCANIO_url_detonation:action_result.status", "==", "success"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        filter_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_4:condition_1:URLSCANIO_url_detonation:action_result.parameter.context.artifact_id", "==", "artifact:*.id"],
        ],
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        urlscanio_no_output(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def urlscanio_update(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('urlscanio_update() called')
    
    template = """%%
{{ \"cef\":{{ \"URLSCAN_ score\": \"{0}\", \"URLSCAN_page_ip\": \"{1}\" }} }}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "urlscanio_no_output:custom_function:urlscanio_score",
        "urlscanio_no_output:custom_function:urlscanio_ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="urlscanio_update")

    Update_with_urlscanio_infromation(container=container)

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_screenshot_1:action_result.status", "==", "success"],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return

def urlscanio_no_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('urlscanio_no_output() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:URLSCANIO_url_detonation:action_result.data.*.verdicts.overall.score', 'filtered-data:filter_5:condition_1:URLSCANIO_url_detonation:action_result.data.*.page.ip'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]
    filtered_results_item_1_1 = [item[1] for item in filtered_results_data_1]

    urlscanio_no_output__urlscanio_score = None
    urlscanio_no_output__urlscanio_ip = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    urlscanio_no_output__urlscanio_score = [ i if i is not None else 'no results' for i in filtered_results_item_1_0]
    urlscanio_no_output__urlscanio_ip = [ i if i is not None else 'no results' for i in filtered_results_item_1_1]

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='urlscanio_no_output:urlscanio_score', value=json.dumps(urlscanio_no_output__urlscanio_score))
    phantom.save_run_data(key='urlscanio_no_output:urlscanio_ip', value=json.dumps(urlscanio_no_output__urlscanio_ip))
    urlscanio_update(container=container)

    return

def Count_VT_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Count_VT_results() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_10:condition_1:artifact:*.id'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Count_VT_results__vt_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    Count_VT_results__vt_count = len(filtered_artifacts_item_1_0)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Count_VT_results:vt_count', value=json.dumps(Count_VT_results__vt_count))
    decision_3(container=container)

    return

def Count_urlscanio_reults(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Count_urlscanio_reults() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_8:condition_1:artifact:*.id'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    Count_urlscanio_reults__urlscanio_count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    Count_urlscanio_reults__urlscanio_count = len(filtered_artifacts_item_1_0)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Count_urlscanio_reults:urlscanio_count', value=json.dumps(Count_urlscanio_reults__urlscanio_count))
    urlscanio_Pin_Text(container=container)

    return

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_4:condition_1:URLSCANIO_url_detonation:action_result.data.*.verdicts.overall.score", ">", 3],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_7:condition_1:URLSCANIO_url_detonation:action_result.parameter.context.artifact_id", "==", "artifact:*.id"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Count_urlscanio_reults(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def VT_Pin_Text(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('VT_Pin_Text() called')
    
    template = """Virus Total: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Count_VT_results:custom_function:vt_count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="VT_Pin_Text")

    no_op_3(container=container)

    return

def urlscanio_Pin_Text(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('urlscanio_Pin_Text() called')
    
    template = """urlscan.io: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Count_urlscanio_reults:custom_function:urlscanio_count",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="urlscanio_Pin_Text")

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Count_VT_results:custom_function:vt_count", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        VT_Pin_Text(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def urlscanio_path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('urlscanio_path() called')

    # collect data for 'urlscanio_path' call

    parameters = []
    
    # build parameters list for 'urlscanio_path' call
    parameters.append({
        'sleep_seconds': 1,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom'], name="urlscanio_path")

    return

def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_3() called')

    formatted_data_1 = phantom.get_format_data(name='format_14')

    phantom.pin(container=container, data=formatted_data_1, message="Number of suspicious ULR with a score > 3", pin_type="card", pin_style="red", name=None)

    return

def Update_with_urlscanio_infromation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_with_urlscanio_infromation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_with_urlscanio_infromation' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.id', 'filtered-data:filter_5:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='urlscanio_update__as_list')

    parameters = []
    
    # build parameters list for 'Update_with_urlscanio_infromation' call
    for i in range(0, len(filtered_artifacts_data_1)):
        if filtered_artifacts_data_1[i][0]:
            phantom.debug(formatted_data_1[i][0])
            parameters.append({
                'data': formatted_data_1[i],
                'overwrite': True,
                'artifact_id': filtered_artifacts_data_1[i][0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_data_1[i][1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], callback=filter_7, name="Update_with_urlscanio_infromation")

    return

def filter_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_9() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.VT_URL_positives", ">=", 3],
        ],
        name="filter_9:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_10(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_10() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_9:condition_1:artifact:*.id", "==", "artifact:*.id"],
        ],
        name="filter_10:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Count_VT_results(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        update_artifact_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def urlscann_no_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('urlscann_no_result() called')
    
    template = """urlsacan.io: no positive scans"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_7:condition_1:URLSCANIO_url_detonation:action_result.status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="urlscann_no_result")

    urlscanio_path(container=container)

    return

def get_report_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_report_1() called')

    # collect data for 'get_report_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['URLSCANIO_url_detonation:action_result.summary.report_uuid', 'URLSCANIO_url_detonation:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_report_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get report", parameters=parameters, assets=['urlscan'], name="get_report_1")

    return

def add_vt_results_to_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_vt_results_to_artifact() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_vt_results_to_artifact' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_3:condition_1:artifact:*.id', 'filtered-data:filter_3:condition_1:artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='vt_update__as_list')

    parameters = []
    
    # build parameters list for 'add_vt_results_to_artifact' call
    for i in range(0, len(filtered_artifacts_data_1)):
        if filtered_artifacts_data_1[i][0]:
            phantom.debug(formatted_data_1[i][0])
            parameters.append({
                'data': formatted_data_1[i],
                'overwrite': True,
                'artifact_id': filtered_artifacts_data_1[i][0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_data_1[i][1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], callback=filter_9, name="add_vt_results_to_artifact")

    return

def no_op_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('no_op_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'no_op_3' call

    parameters = []
    
    # build parameters list for 'no_op_3' call
    parameters.append({
        'sleep_seconds': 1,
    })

    phantom.act(action="no op", parameters=parameters, assets=['phantom'], callback=format_14, name="no_op_3")

    return

def format_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_14() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "VT_Pin_Text:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_14")

    pin_3(container=container)

    return

def filter_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_12() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_4:condition_1:URLSCANIO_url_detonation:action_result.data.*.verdicts.overall.score", "==", ""],
        ],
        name="filter_12:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_13(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_13() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_12:condition_1:URLSCANIO_url_detonation:action_result.parameter.context.artifact_id", "==", "filtered-data:filter_1:condition_1:artifact:*.id"],
        ],
        name="filter_13:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_comment_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def add_comment_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_5() called')

    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_13:condition_1:artifact:*.id'])

    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    phantom.comment(container=container, comment=filtered_artifacts_item_1_0)

    return

def update_artifact_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('update_artifact_8() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'update_artifact_8' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_10:condition_1:artifact:*.id', 'filtered-data:filter_10:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_8' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'data': "{ \"cef\": {\"suspicious_flag\": \"true\"}}",
                'overwrite': "",
                'artifact_id': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact", parameters=parameters, assets=['phantom utilities'], name="update_artifact_8")

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