rule slack_key
{
    meta:
        type = "slack key"

    strings:
        $slack_key = /xoxb-\d+-\w{24}/

    condition:
        $slack_key
}