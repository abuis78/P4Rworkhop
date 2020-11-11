"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Filter_1_IF_Email_Artifact' block
    Filter_1_IF_Email_Artifact(container=container)

    return

"""
This Filter  is a check if the Artifact  name == 
Email Artifact
"""
def Filter_1_IF_Email_Artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_1_IF_Email_Artifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Email Artifact", "in", "artifact:*.name"],
        ],
        name="Filter_1_IF_Email_Artifact:condition_1")

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
            ["filtered-data:Filter_1_IF_Email_Artifact:condition_1:artifact:*.cef.emailHeaders.X-Spam-Status", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        XSpamStatus_status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        XSpamStatus_score(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        XSpamStatus_required(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        XSpamStatus_tests(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def XSpamStatus_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_status() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_1_IF_Email_Artifact:condition_1:artifact:*.cef.emailHeaders.X-Spam-Status'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    XSpamStatus_status__XSpamStatus_status = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    for item in filtered_artifacts_item_1_0:
        if item:
            stripped_XSpamStatus_status = re.findall(r'^(\w*)',item)
            XSpamStatus_status__XSpamStatus_status = stripped_XSpamStatus_status[0]
            phantom.debug(message="stripped_XSpamStatus_status: {}".format(XSpamStatus_status__XSpamStatus_status)) 
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='XSpamStatus_status:XSpamStatus_status', value=json.dumps(XSpamStatus_status__XSpamStatus_status))
    XSpamStatus_status_decision(container=container)

    return

def XSpamStatus_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_score() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_1_IF_Email_Artifact:condition_1:artifact:*.cef.emailHeaders.X-Spam-Status'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    XSpamStatus_score__XSpamStatus_score = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    for item in filtered_artifacts_item_1_0:
        if item:
            stripped_XSpamStatus_score = re.findall(r'^.*score=([0-9]*\.[0-9]*)',item)
            XSpamStatus_score__XSpamStatus_score = stripped_XSpamStatus_score[0]
            phantom.debug(message="stripped_XSpamStatus_score: {}".format(XSpamStatus_score__XSpamStatus_score)) 
            XSpamStatus_score__XSpamStatus_score = float(XSpamStatus_score__XSpamStatus_score)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='XSpamStatus_score:XSpamStatus_score', value=json.dumps(XSpamStatus_score__XSpamStatus_score))
    join_score_less_than_required(container=container)

    return

def XSpamStatus_required(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_required() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_1_IF_Email_Artifact:condition_1:artifact:*.cef.emailHeaders.X-Spam-Status'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    XSpamStatus_required__XSpamStatus_required = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    for item in filtered_artifacts_item_1_0:
        if item:
            stripped_XSpamStatus_required = re.findall(r'^.*required=([0-9]*\.[0-9]*)',item)
            XSpamStatus_required__XSpamStatus_required = stripped_XSpamStatus_required[0]
            phantom.debug(message="XSpamStatus_required: {}".format(XSpamStatus_required__XSpamStatus_required)) 
            XSpamStatus_required__XSpamStatus_required = float(XSpamStatus_required__XSpamStatus_required)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='XSpamStatus_required:XSpamStatus_required', value=json.dumps(XSpamStatus_required__XSpamStatus_required))
    join_score_less_than_required(container=container)

    return

def XSpamStatus_tests(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_tests() called')
    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:Filter_1_IF_Email_Artifact:condition_1:artifact:*.cef.emailHeaders.X-Spam-Status'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    XSpamStatus_tests__XSpamStatus_tests = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    for item in filtered_artifacts_item_1_0:
        if item:
            stripped_XSpamStatus_tests = re.findall(r'^.*tests=(([^\s]+))',item)
            XSpamStatus_tests__XSpamStatus_tests = stripped_XSpamStatus_tests[0]
            phantom.debug(message="XSpamStatus_tests: {}".format(XSpamStatus_tests__XSpamStatus_tests)) 

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='XSpamStatus_tests:XSpamStatus_tests', value=json.dumps(XSpamStatus_tests__XSpamStatus_tests))
    XSpamStatus_tests_performed(container=container)

    return

"""
GREEN: XSpamStatus_score < than XSpamStatus_required

PURPLE: Else
"""
def score_less_than_required(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('score_less_than_required() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["XSpamStatus_score:custom_function:XSpamStatus_score", "<", "XSpamStatus_required:custom_function:XSpamStatus_required"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        XSpamStatus_score_status_low(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    XSpamStatus_score_above_KPI(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_score_less_than_required(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_score_less_than_required() called')

    # no callbacks to check, call connected block "score_less_than_required"
    phantom.save_run_data(key='join_score_less_than_required_called', value='score_less_than_required', auto=True)

    score_less_than_required(container=container, handle=handle)
    
    return

def XSpamStatus_score_status_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_score_status_low() called')
    
    template = """The Score is low: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_score:custom_function:XSpamStatus_score",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="XSpamStatus_score_status_low")

    join_Summery_XSpamStatus_Score(container=container)

    return

def XSpamStatus_score_above_KPI(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_score_above_KPI() called')
    
    template = """The score is above KPI. (Score: {0} - KPI: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_score:custom_function:XSpamStatus_score",
        "XSpamStatus_required:custom_function:XSpamStatus_required",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="XSpamStatus_score_above_KPI")

    join_Summery_XSpamStatus_Score(container=container)

    return

"""
GREEN: If XSpamStatus_status == NO

PURPLE: Else
"""
def XSpamStatus_status_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_status_decision() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["XSpamStatus_status:custom_function:XSpamStatus_status", "==", "No"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        XSpamStatus_status_NO(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    XSpamStatus_status_YES(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def XSpamStatus_status_NO(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_status_NO() called')
    
    template = """Not a SPAM"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_status:custom_function:XSpamStatus_status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="XSpamStatus_status_NO")

    HUD_gray(container=container)

    return

def XSpamStatus_status_YES(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_status_YES() called')
    
    template = """is suspected to be a spam mail"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_status:custom_function:XSpamStatus_status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="XSpamStatus_status_YES")

    HUD_red_and_severity_medium(container=container)

    return

def XSpamStatus_tests_performed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('XSpamStatus_tests_performed() called')
    
    template = """These tests could be done:
-------------------------------------------------------
{0}
-------------------------------------------------------
For more information please read: https://spamassassin.apache.org/old/tests_3_3_x.html"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_tests:custom_function:XSpamStatus_tests",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="XSpamStatus_tests_performed")

    join_Summery(container=container)

    return

def HUD_gray(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('HUD_gray() called')

    formatted_data_1 = phantom.get_format_data(name='XSpamStatus_status_NO')

    phantom.pin(container=container, data=formatted_data_1, message="XSpamStatus", pin_type="card", pin_style="grey", name=None)
    join_Summery_XSpamStatus(container=container)

    return

def HUD_red_and_severity_medium(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('HUD_red_and_severity_medium() called')

    formatted_data_1 = phantom.get_format_data(name='XSpamStatus_status_YES__as_list')

    phantom.pin(container=container, data=formatted_data_1, message="XSpamStatus", pin_type="card", pin_style="red", name=None)

    phantom.set_severity(container=container, severity="Medium")
    join_Summery_XSpamStatus(container=container)

    return

def Summery(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summery() called')
    
    template = """Spam Assassin result:

## XSpamStatus ##
{0}

## XSpam score ##
{1}

-------- XSpam test -------
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "Summery_XSpamStatus:formatted_data",
        "Summery_XSpamStatus_Score:formatted_data",
        "XSpamStatus_tests:custom_function:XSpamStatus_tests",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summery")

    Save_Data_in_Object(container=container)

    return

def join_Summery(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Summery() called')

    # no callbacks to check, call connected block "Summery"
    phantom.save_run_data(key='join_Summery_called', value='Summery', auto=True)

    Summery(container=container, handle=handle)
    
    return

def Save_Data_in_Object(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Save_Data_in_Object() called')
    
    id_value = container.get('id', None)
    formatted_data_1 = phantom.get_format_data(name='Summery')

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

    return

def Summery_XSpamStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summery_XSpamStatus() called')
    
    template = """{0}
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_status_NO:formatted_data",
        "XSpamStatus_status_NO:formatted_data.*",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summery_XSpamStatus")

    join_Summery(container=container)

    return

def join_Summery_XSpamStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Summery_XSpamStatus() called')

    # no callbacks to check, call connected block "Summery_XSpamStatus"
    phantom.save_run_data(key='join_Summery_XSpamStatus_called', value='Summery_XSpamStatus', auto=True)

    Summery_XSpamStatus(container=container, handle=handle)
    
    return

def Summery_XSpamStatus_Score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Summery_XSpamStatus_Score() called')
    
    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "XSpamStatus_score_status_low:formatted_data",
        "XSpamStatus_score_above_KPI:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Summery_XSpamStatus_Score")

    join_Summery(container=container)

    return

def join_Summery_XSpamStatus_Score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Summery_XSpamStatus_Score() called')

    # no callbacks to check, call connected block "Summery_XSpamStatus_Score"
    phantom.save_run_data(key='join_Summery_XSpamStatus_Score_called', value='Summery_XSpamStatus_Score', auto=True)

    Summery_XSpamStatus_Score(container=container, handle=handle)
    
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