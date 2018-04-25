from setuptools import setup

setup(
    name='AutoInject',
    version='0.1.0',
    packages=['AutoInject'],
    include_package_data=True,
    install_requires=[
        'apscheduler',
        'beautifulsoup4',
    	'cve-search',
        'flask',
        'flask-admin',
        'flask-login',
        'flask-mongoengine',
        'lxml',
        'ply',
        'psutil',
        'pygments',
        'pymongo'
    ],
)
