from distutils.core import setup
import os


def package_files(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append('../' + os.path.join(path, filename))
    return paths


extra_files = package_files('cyhy_report/assets')

setup(
    name='cyhy-reports',
    version='0.0.2',
    author='Mark Feldhousen Jr.',
    author_email='mark.feldhousen@hq.dhs.gov',
    packages=['cyhy_report',
              'cyhy_report.bod_scorecard',
              'cyhy_report.customer',
              'cyhy_report.cybex_scorecard',
              'cyhy_report.scorecard',
              'cyhy_report.m1513_scorecard'],
    package_data={'cyhy_report.customer': ['*.mustache'],
                  'cyhy_report.bod_scorecard': ['*.mustache', '*.js'],
                  'cyhy_report.cybex_scorecard': ['*.mustache', '*.js'],
                  'cyhy_report.scorecard': ['*.mustache'],
                  'cyhy_report.m1513_scorecard': ['*.mustache', '*.js'],
                  '': extra_files},
    scripts=['bin/cyhy-report',
             'bin/cyhy-scorecard',
             'bin/cyhy-bod-scorecard',
             'bin/cyhy-cybex-scorecard',
             'bin/cyhy-m1513-scorecard'],
    # url='http://pypi.python.org/pypi/CyHy/',
    license='LICENSE.txt',
    description='Reporting components for Cyber Hygiene',
    # long_description=open('README.txt').read(),
    install_requires=[
        "cyhy-core >= 0.0.2",
        # pip install of basemap currently fails; see requirements.txt
        # "basemap >= 1.0.6",
        "matplotlib == 1.5.3",
        "numpy == 1.10.4",
        "pandas == 0.19.1",
        "python-dateutil >= 2.2",
        "netaddr >= 0.7.10",
        "pystache >= 0.5.3",
        "progressbar >=2.3-dev",
        "docopt >= 0.6.2",
        "unicodecsv >= 0.9.4",
        "pyPdf >= 1.13",
        "requests >= 2.21.0"
    ]
)
