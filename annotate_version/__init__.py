__version__ = "0.2.0"

import codecs
import io
import logging
from pathlib import Path
import pathlib
import re
import sys
import pefile
import ndjson
import os
from plumbum import ProcessExecutionError, local
import requests
import zstandard

CHANGEAPI_URL = os.getenv("CHANGEAPI_URL")
CHANGEAPI_MOLLY_GUARD = os.getenv("CHANGEAPI_MOLLY_GUARD")
DATAAPI_URL = os.getenv("DATAAPI_URL")


def main():
    logging.basicConfig(format="%(asctime)s | %(message)s", level=logging.INFO)
    LOG = logging.getLogger()
    builds_url = f"{CHANGEAPI_URL}/builds/public"

    builds = requests.get(builds_url).json()

    for bid, build in builds.items():
        if "version" not in build or build["version"] is None:
            depot = None
            manifests = build["manifests"]
            for d in ["238962", "238961"]:
                if d in manifests:
                    depot = d
                    break
            manifest = manifests[depot]
            gid = manifest["gid"]

            mf_url = f"{DATAAPI_URL}/idxz/{depot}/{gid}/loose"
            resp = requests.get(mf_url)
            if resp.status_code == 200:
                LOG.info(mf_url)
                dctx = zstandard.ZstdDecompressor()
                with dctx.stream_reader(io.BytesIO(resp.content), closefd=True) as fh:
                    with codecs.getreader("UTF-8")(fh) as fh:
                        cands = []
                        reader = ndjson.reader(fh)
                        exe_urls = []
                        for row in reader:
                            if row["path"].endswith('.exe'):
                                hash = row["sha256"]
                                exe_url = f"{DATAAPI_URL}/cad/{hash}"
                                exe_urls.append(exe_url)
                                exe_resp = requests.get(exe_url)
                                if exe_resp.status_code == 200:
                                    try:
                                        data = exe_resp.content
                                        pe = pefile.PE(
                                            data=data, fast_load=True
                                        )
                                    except pefile.PEFormatError as e:
                                        p = pathlib.Path("C:/Temp") / f"{hash}.exe"
                                        p.write_bytes(data)
                                        LOG.info(row)
                                        LOG.fatal(f"{e}: Bogus EXE: {p}")
                                        raise
                                    r = re.compile(b"(?:release )?tags/(\d[-\da-z. ]{4,40})")
                                    img = data = pe.get_memory_mapped_image()
                                    for section in pe.sections:
                                        va = section.VirtualAddress
                                        for it in r.finditer(
                                            img, va, va + section.Misc_VirtualSize
                                        ):
                                            cands.append(it.group(1))
                                else:
                                    LOG.warn(
                                        f"missing {exe_url}, {exe_resp.status_code}; {row['path']}"
                                    )
                        if len(cands):
                            cands = sorted(cands, key=len, reverse=True)
                            version = cands[0]
                            print(cands)
                            print(version)
                            resp = requests.put(
                                f"{builds_url}/{bid}/version",
                                params={
                                    "version": version,
                                    "molly_guard": CHANGEAPI_MOLLY_GUARD,
                                },
                            )
                            LOG.info(resp.status_code)
                        else:
                            LOG.error(
                                f"no candidates found for {depot}/{gid}"
                            )
                            for url in exe_urls:
                                LOG.error(url)


if __name__ == "__main__":
    main()
