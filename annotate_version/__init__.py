__version__ = '0.1.0'

import codecs
import logging
from pathlib import Path
import ndjson
import os
from plumbum import ProcessExecutionError, local
import requests
import zstandard

def main():
    logging.basicConfig(format="%(asctime)s | %(message)s", level=logging.INFO)
    LOG = logging.getLogger()
    root_dir = Path(os.getenv('ROOT_DIR'))
    index_dir = root_dir / 'index'
    data_dir = root_dir / 'data'
    builds_url = f'{os.getenv("API_URL")}/builds/public'
    molly_guard = os.getenv('MOLLY_GUARD')

    builds = requests.get(builds_url).json()

    cat = local['cat']
    grep = local['grep']
    strings = local['strings']
    zstdcat = local['zstdcat']

    for bid, build in builds.items():
        if 'version' not in build or build['version'] is None:
            depot = None
            manifests = build['manifests']
            for d in ['238962', '238961']:
                if d in manifests:
                    depot = d
                    break
            manifest = manifests[depot]

            path = index_dir / f'{depot}/{manifest}-loose.ndjson.zst'
            if path.exists():
                LOG.info(path)
                fh = path.open(mode='rb')
                dctx = zstandard.ZstdDecompressor()
                with dctx.stream_reader(fh, closefd=True) as fh:    
                    with codecs.getreader('UTF-8')(fh) as fh:
                        cands = []
                        reader = ndjson.reader(fh)
                        for row in reader:
                            if '.exe' in row["path"]:
                                hash = row["sha256"]
                                if row["comp"]:
                                    path = data_dir / f'{hash[:2]}/{hash}.bin.zst'
                                    extractor = zstdcat[path]
                                else:
                                    path = data_dir / f'{hash[:2]}/{hash}.bin'
                                    extractor = cat[path]
                                try:
                                    pipe = extractor | strings['-d', '-n', '14'] | grep['release tags/']
                                    cands.extend(pipe().splitlines())
                                except ProcessExecutionError:
                                    pass
                        if len(cands):
                            version = sorted(cands, key=len)[-1]
                            version = version.partition('/')[2]
                            print(version)
                            resp = requests.put(f'{builds_url}/{bid}/version', params={'version': version, 'molly_guard': molly_guard})
                            LOG.info(resp.status_code)

if __name__ == '__main__':
    main()