#!/usr/bin/python3
from pathlib import Path
import json
import os
import subprocess
import shutil
import sys
import ReviewBot


PROMPT = """
check all files in @BUILD for zero-day vulnerabilities and report ACCEPTABLE if none found otherwise REJECT
"""


class FactoryReviewAI(ReviewBot.ReviewBot):
    """Your custom bot implementation."""

    def __init__(self, *args, **kwargs):
        ReviewBot.ReviewBot.__init__(self, *args, **kwargs)
        # Configure bot options here
        self.request_default_return = None

    @staticmethod
    def checkout_package(scm, target_project, target_package, pathname, **kwargs):

        r = scm.checkout_package(
            target_project,
            target_package,
            pathname,
            **kwargs
        )

        sourcedir = Path(pathname).absolute() / target_package
        builddir = sourcedir / "BUILD"
        unp = subprocess.run(["rpmbuild", "--nodeps",
                        "--define", f"%_sourcedir {sourcedir}",
                        "--define", f"%_builddir {builddir}",
                        "-bp", f"{target_package}.spec"],
                        cwd=sourcedir, timeout=30, capture_output=True)
        return r

    def check_source_submission(self, source_project, source_package, source_revision,
                                target_project, target_package):
        """
        Main review logic - override this method in your bot!
        This is called for each source submit/pull request.
        """

        # Information messages are visible at stdout when using "--verbose" option
        print(f"Checking {source_package}: {source_project} -> {target_project}")

        # Checkout and see if renaming package screws up version parsing.
        copath = os.path.expanduser(f'~/co/{self.request.reqid}')
        if os.path.exists(copath):
            self.logger.info(f'directory {copath} already exists, skipping check')
            return
        os.makedirs(copath)
        os.chdir(copath)

        try:
            FactoryReviewAI.checkout_package(self.scm, target_project, target_package, pathname=copath,
                                         server_service_files=True, expand_link=True)
            os.rename(target_package, '_old')
        except HTTPError as e:
            if e.code == 404:
                self.logger.info(f'target package does not exist {target_project}/{target_package}')
            else:
                raise e

        FactoryReviewAI.checkout_package(self.scm, source_project, source_package, revision=source_revision,
                                     pathname=copath, server_service_files=True, expand_link=True)
        os.rename(source_package, target_package)

        gemini = subprocess.run(["/usr/bin/gemini", "-o", "json", "-p", PROMPT],
                       cwd=target_package, timeout=600, capture_output=True)
        resp = json.loads(gemini)

        if not "ACCEPTABLE" in resp.response:
            print(f"result: {resp.response}")




class CommandLineInterface(ReviewBot.CommandLineInterface):
    def __init__(self, *args, **kwargs):
        ReviewBot.CommandLineInterface.__init__(self, args, kwargs)
        self.clazz = FactoryReviewAI


if __name__ == "__main__":
    app = CommandLineInterface()
    sys.exit(app.main())
