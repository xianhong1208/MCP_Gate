# Marketplace Offline Image Tars

Place the docker image tar file of each catalog entry here (used for offline "install").

- File-name convention: `<catalog_id>.tar` (e.g. `perplexity-ask.tar`);
  the name can also be overridden in the catalog yaml with `image_tar:`, which supports the
  `{tag}` / `{image}` / `{id}` placeholders, e.g. `image_tar: my-mcp_{tag}.tar.gz` -- when upgrading,
  only `docker.tag` changes and the file name follows automatically.
- gzip compression (`.tar.gz`) is supported; docker load reads it natively, no need to decompress.
- How to produce one: `docker save -o <catalog_id>.tar <image>:<tag>`
- "Install" = the backend loads this tar via the docker SDK (equivalent to `docker load -i`);
  "Deploy" = start the container (the image must already be installed).
