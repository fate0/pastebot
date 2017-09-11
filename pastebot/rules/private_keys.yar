rule ssh_private_key
{
    meta:
        type = "SSH 私钥"

    strings:
        $ssh_private_key = /BEGIN RSA PRIVATE.{640,}END RSA PRIVATE/s

    condition:
        $ssh_private_key
}


rule pgp_private_key
{
    meta:
        type = "PGP 私钥"

    strings:
        $pgp_private_key = /BEGIN PGP PRIVATE.{640,}END PGP PRIVATE/s

    condition:
        $pgp_private_key
}