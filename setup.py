from setuptools import setup, find_packages

with open('README.md') as readme_file:
    README = readme_file.read()

with open('HISTORY.md') as history_file:
    HISTORY = history_file.read()

setup_args = dict(
    name='Tapo',
    version='0.0.1',
    description='A module for controlling the Tp-link Tapo P100/P110 plugs',
    long_description_content_type="text/markdown",
    long_description=README,
    license='MIT',
    packages=find_packages(),
    author='synapsengymnastik',
    author_email='synapsengymnastik@gmail.com',
    keywords=['Tapo', 'Tp-Link', 'P100'],
    url='https://github.com/synapsengymnastik/Tapo',
    download_url='https://github.com/synapsengymnastik/Tapo'
)

install_requires = [
    'pycryptodome==3.9.8',
    'pkcs7==0.1.2',
    'requests==2.24.0',
]

if __name__ == '__main__':
    setup(**setup_args, install_requires=install_requires)
