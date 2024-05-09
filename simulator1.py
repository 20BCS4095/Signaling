import subprocess

curl_command1 = [
    'curl',
    '-X', 'POST',
    '-v',
    '-d', '{"version":"1.0.0","targetService":"mainApp","blocking":true,"encoding":"text","command":"Signaling PUB_setSignalingConfig 5432 600 TGF1cmVudCB3cm90 httpOnly"}',
    'http://10.224.1.254/hp/device/WSFramework/underware/v1/command'
]

try:
    result1 = subprocess.run(curl_command1, capture_output=True, text=True)
    print("Curl output:", result1)
except subprocess.CalledProcessError as e:
    print("Error executing curl command:", e)

command2 = "Signaling PUB_setHttpSignalingConfig " + update_config_data["PollingDelay"] + " " + update_config_data["PollingTimeout"] + " " + update_config_data["RetryGraceCount"] + " " + update_config_data["RandomWindow"] + " " + update_config_data["PrinterStatusRatio"] + " " + update_config_data["MaxGetsBetweenPosts"] + " " + update_config_data["URL"]

curl_command2 = [
    'curl',
    '-X', 'POST',
    '-v',
    '-d', '{"version":"1.0.0","targetService":"mainApp","blocking":true,"encoding":"text","command":"' + command2 + '"}',
    'http://10.224.1.254/hp/device/WSFramework/underware/v1/command'
]

try:
    result2 = subprocess.run(curl_command2, capture_output=True, text=True)
    print("Curl output:", result2)
except subprocess.CalledProcessError as e:
    print("Error executing curl command:", e)
