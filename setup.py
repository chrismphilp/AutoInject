from setuptools import setup

setup(
    name='AutoInject',
    version='0.1.0',
    packages=['AutoInject'],
    include_package_data=True,
    install_requires=[
    	'cve-search',
        'flask',
        'flask-admin',
        'flask-login',
        'flask-mongoengine',
        'ply',
        'pygments'
    ],
)
