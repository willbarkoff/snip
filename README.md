# Snip

> A super simple URL shortener.

To set up snip, first, copy the [`config.sample.toml`](./config.sample.toml) file to `config.toml`. You can then populate it with your values. You can then run snip and head over to the /setup page to create a user account.

The database schema is stored in [schema.sql](schema.sql). Running that on a MySQL database will populate it with the required structure for snip.

Snip allows you to preview a link before you visit it. Just go to /preview/\[link\] to preview the link.