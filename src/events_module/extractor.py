import subprocess
import json


def get_recent_events():

    ps_command = """
    $startTime = (Get-Date).AddHours(-24)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4800; StartTime=$startTime} -ErrorAction SilentlyContinue | 
    Select-Object TimeCreated, Id | 
    ConvertTo-Json
    """

    # Execute the command from Python
    process = subprocess.run(
        ["powershell", "-Command", ps_command], capture_output=True, text=True
    )

    # If no events occurred, powershell returns nothing
    if not process.stdout.strip():
        return []

    # Let Python parse the clean JSON!
    events = json.loads(process.stdout)
    return events
