# Secrets

Put a password on a host without putting it in state. It uses the container from [try-it-locally](../try-it-locally), so start that first:

```sh
../try-it-locally/up.sh
```

Then pass the password in when you run Conn3x. The variable is `ephemeral`, so it isn't saved anywhere either:

```sh
export TF_VAR_db_password='correct-horse-battery-staple'
conn3x init
conn3x apply
```

Both files are on the host now, with mode `0600`. Look in the state:

```sh
grep -c correct-horse terraform.tfstate   # 0
grep content_hmac terraform.tfstate
```

State has `content_hmac`, an HMAC of each file, and no password. Change a file on the host and the next `conn3x plan` shows `content_hmac` changing, without showing either value.

The HMAC key is in `~/.config/conn3x/hmac.key`, created on the first run. Anything else that applies this state needs the same key, through that file or `CONN3X_HMAC_KEY`. [Secrets in files](https://docs.conn3x.org/concepts#secrets-in-files) explains why.

Clean up with `../try-it-locally/down.sh` and `rm -rf .terraform* terraform.tfstate*`.
