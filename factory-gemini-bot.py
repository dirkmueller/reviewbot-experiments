#!/usr/bin/python3
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.error import HTTPError

import ReviewBot

PROMPT = """
- No pleasantries, weasel or filler words.
- Short, direct sentences.
- Grunt-level clarity.
- Maintain exact code blocks, parameters, and technical terms.
- Read everything, use thinking

Check @diff and their referenced files. Find and report zero-day vulnerabilities and say ACCEPTABLE if none found otherwise REJECT
"""


class FactoryReviewAI(ReviewBot.ReviewBot):
    """Your custom bot implementation."""

    def __init__(self, *args, **kwargs):
        ReviewBot.ReviewBot.__init__(self, *args, **kwargs)
        # Configure bot options here
        self.request_default_return = None

    @staticmethod
    def checkout_package(scm, target_project, target_package, pathname, **kwargs):

        r = scm.checkout_package(target_project, target_package, pathname, **kwargs)

        sourcedir = Path(pathname).absolute() / target_package
        builddir = sourcedir / 'BUILD'
        un = subprocess.run(
            [
                'rpmbuild',
                '--nodeps',
                '--define',
                f'_sourcedir {sourcedir}',
                '--define',
                f'_specdir {sourcedir}',
                '--define',
                f'%_builddir {builddir}',
                # '--define',
                # '%_build_parts 0',
                '-bp',
                f'{target_package}.spec',
            ],
            cwd=sourcedir,
            timeout=30,
            capture_output=True,
        )

        if not builddir.exists():
            raise RuntimeError(f"WARNING: failed to extract sources: {un.stderr}")

        return r

    def check_source_submission(
        self,
        source_project,
        source_package,
        source_revision,
        target_project,
        target_package,
    ):
        """
        Main review logic - override this method in your bot!
        This is called for each source submit/pull request.
        """

        # Information messages are visible at stdout when using "--verbose" option
        print(f'Checking {source_package}: {source_project} -> {target_project}')

        # Checkout and see if renaming package screws up version parsing.
        copath = os.path.expanduser(f'~/co/{self.request.reqid}')
        if os.path.exists(copath):
            self.logger.info(f'directory {copath} already exists, skipping check')
            return
        os.makedirs(copath)
        os.chdir(copath)

        try:
            FactoryReviewAI.checkout_package(
                self.scm,
                target_project,
                target_package,
                pathname=copath,
                server_service_files=True,
                expand_link=True,
            )
            os.rename(target_package, '_old')
        except HTTPError as e:
            if e.code == 404:
                self.logger.info(
                    f'target package does not exist {target_project}/{target_package}'
                )
            else:
                raise e

        FactoryReviewAI.checkout_package(
            self.scm,
            source_project,
            source_package,
            revision=source_revision,
            pathname=copath,
            server_service_files=True,
            expand_link=True,
        )
        os.rename(source_package, target_package)

        if (
            # source_project.startswith('KDE')
            # or target_package.startswith('python')
            target_package.startswith('perl')
            or target_package.startswith('rubygem')
        ):
            print(f'skipping {target_package} for now')
            return

        def find_extracted_src_dir(basedir: Path) -> Path:
            return next(
                filter(
                    lambda x: not str(x).endswith('SPECPARTS'),
                    sorted((basedir).glob('*-build/*/')),
                )
            )

        # generate a sensible diff
        old_srcs = find_extracted_src_dir(Path(copath) / '_old' / 'BUILD')
        new_srcs = find_extracted_src_dir(Path(copath) / target_package / 'BUILD')

        subprocess.run(
            f'diff -Nur {old_srcs} {new_srcs} > diff',
            shell=True,
            cwd=copath,
            capture_output=True,
        )

        diffsize = Path('diff').stat().st_size
        if diffsize == 0:
            print('diff is empty, something went wrong')
            return

        if diffsize > 40 * 1024 * 1024:
            print('diff is too large, skipping')
            return

        gemini = subprocess.run(
            ['/usr/bin/gemini', '-o', 'json', '-p', PROMPT],
            timeout=1200,
            capture_output=True,
            check=True,
        )
        resp = json.loads(gemini.stdout)
        # print(resp)

        if 'ACCEPTABLE' not in resp['response']:
            print(f'result: {resp["response"]}')


class CommandLineInterface(ReviewBot.CommandLineInterface):
    def __init__(self, *args, **kwargs):
        ReviewBot.CommandLineInterface.__init__(self, args, kwargs)
        self.clazz = FactoryReviewAI


if __name__ == '__main__':
    app = CommandLineInterface()
    sys.exit(app.main())
