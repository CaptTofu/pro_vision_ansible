# pro_vision_ansible

This module is a python module containing common methods needed for the HP Pro Vision modules for Ansible (HP 3800, etc). This code used to be contained in each module but it was found that there was a severe case of code duplication. This code is specific to both Ansible and the HP Pro Vision switches. The code that is specific only to HP switches (or any switch) has been moved to a module called "switchssh", which contains methods that make talking to switches easier and "expect"-like. 
