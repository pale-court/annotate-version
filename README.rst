A tool to extract the game version from Path of Exile executables.

Required environment variables:

* ``ROOT_DIR``: local storage with index and data trees, needs to contain the
  loose index and the deduplicated executable files;
* ``API_URL``: URL to a changeapi server to query for build lists with existing
  versions and to post new versions to;
* ``MOLLY_GUARD``: secret passphrase for write access to the changeapi.

This tool preferably runs as a periodic systemd timer to poll whether any new
unversioned releases may have appeared. Depending on the ingestion speed of
data processing there may be a delay between when a new release appears in
changeapi and the time an executable is actually available to be processed.

System tools required: ``cat``, ``grep``, ``strings``, ``zstdcat``
