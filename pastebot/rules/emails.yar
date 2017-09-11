rule emails
{
    meta:
        type = "邮箱"

    strings:
        $email = /\b[\w\._%+-]+@[\w\.-]+\.\w{2,10}\b/

    condition:
        #email > 50
}