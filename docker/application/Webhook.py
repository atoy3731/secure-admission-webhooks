from flask import Flask, request, jsonify
import os, base64
import jsonpatch
import random

app = Flask(__name__)

CERT = os.environ.get('CERT', 'certs/cert.pem')
KEY = os.environ.get('KEY', 'certs/key.pem')


@app.route('/mutate/randomuid', methods=['POST'])
def randomuid_webhook_mutate():
    """
    Ensures pods and deployments are ran as a Random UID with 'root' group ownership.
    :return:
    """
    request_info = request.get_json()

    uid = _get_random_uid()

    if request_info['request']['kind']['kind'] == 'Deployment':
        patches = [
            {"op": "add", "path": "/spec/template/spec/securityContext/runAsUser", "value": uid},
            {"op": "add", "path": "/spec/template/spec/securityContext/runAsGroup", "value": 0},
            {"op": "add", "path": "/spec/template/spec/securityContext/fsGroup", "value": 0}
        ]
    elif request_info['request']['kind']['kind'] == 'Pod':
        patches = [
            {"op": "add", "path": "/spec/securityContext/runAsUser", "value": uid},
            {"op": "add", "path": "/spec/securityContext/runAsGroup", "value": 0},
            {"op": "add", "path": "/spec/securityContext/fsGroup", "value": 0}
        ]
    else:
        patches = []

    return _admission_mutation_response(True, "Ensuring random UID", json_patch=jsonpatch.JsonPatch(patches))


@app.route('/validate/noprivilege', methods=['POST'])
def block_privilege_webhook_validate():
    """
    Blocks deployment and pod creation if 'allowPrivilegeEscalation' is enabled.
    :return: N/A
    """
    request_json = request.get_json()

    if request_json['request']['kind']['kind'] == 'Deployment':
        print('deployment')
    elif request_json['request']['kind']['kind'] == 'Pod':
        if 'securityContext' in request_json["request"]["object"]["spec"] and 'allowPrivilegeEscalation' in request_json["request"]["object"]["spec"]['securityContext'] and request_json["request"]["object"]["spec"]['securityContext']['allowPrivilegeEscalation']:
            return _admission_validation_response(False, "Privilege escalation not allowed.")

        for container_spec in request_json["request"]["object"]["spec"]["containers"]:
            if 'securityContext' in container_spec and 'allowPrivilegeEscalation' in container_spec['securityContext'] and container_spec['securityContext']['allowPrivilegeEscalation']:
                return _admission_validation_response(False, "Privilege escalation not allowed.")

    return _admission_validation_response(True, "Privilege escalation not detected. Approved.")


def _admission_mutation_response(allowed, message, json_patch):
    """
    Get the valid response object for webhook.
    :param allowed: Whether the admissino was allowed.
    :param message: Message for logging.
    :param json_patch: Patch to be appied.
    :return:
    """
    base64_patch = base64.b64encode(json_patch.to_string().encode("utf-8")).decode("utf-8")
    return jsonify({
        "response": {
            "allowed": allowed,
             "status": {
                 "message": message
            },
             "patchType": "JSONPatch",
             "patch": base64_patch
        }
    })


def _admission_validation_response(allowed, message):
    """
    Response for validating webhook.
    :param allowed: Whether the action is allowed or not.
    :param message: Status message
    :return:
    """
    return jsonify({
        "response": {
            "allowed": allowed,
            "status": {
                "message": message
            }
        }
    })

def _get_random_uid():
    """
    Gets a random Integer for the UID.
    :return: Random UID
    """
    return random.randint(100000, 999999)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443, ssl_context=(CERT, KEY))
