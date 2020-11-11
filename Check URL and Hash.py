"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'playbook_P4R_final_version_IOCs_URL_mobile_1' block
    playbook_P4R_final_version_IOCs_URL_mobile_1(container=container)

    return

def playbook_P4R_final_version_IOCs_URL_mobile_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_P4R_final_version_IOCs_URL_mobile_1() called')
    
    # call playbook "P4R_final_version/IOCs_URL_mobile", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="P4R_final_version/IOCs_URL_mobile", container=container, name="playbook_P4R_final_version_IOCs_URL_mobile_1", callback=playbook_P4R_final_version_IOCs_File_mobile_1)

    return

def playbook_P4R_final_version_IOCs_File_mobile_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_P4R_final_version_IOCs_File_mobile_1() called')
    
    # call playbook "P4R_final_version/IOCs_File_mobile", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="P4R_final_version/IOCs_File_mobile", container=container, name="playbook_P4R_final_version_IOCs_File_mobile_1")

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