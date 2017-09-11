rule hash32
{
    meta:
        type = "hash32"

    strings:
        $hash32 = /\b([A-Fa-f\d]{32})\b/

    condition:
        #hash32 > 50
}