# Python Honeypot

## Overview:

This is a simple honeypot coded entirely in Python. It consists of two distinct parts:

- A listener that listens on defined ports and responds with an error message to any traffic delivered to those ports. It then logs the data and saves it to a ```.json``` file.
- A SIEM constructed with Streamlit Python that takes the ```.json``` file and analyzes it. It also includes an LLM assistant that is very similar in design to my other [LLM Log Analyzer Project](https://github.com/Tori-Tech/LLM-Log-Analyzer).
- A PII stripper that ensures no sensitive information is ever passed to the LLM.


## Prerequisites:

A properly configured Ollama installation is required to use this project to its fullest. 

Note that this project will work with any LLM. I will be using the ```llama3.2:3b``` model because it is lightweight and therefore most appropriate for my setup. If your hardware is capable of hosting more powerful LLMs, or if you possess an OpenAI API key, feel free to substitute accordingly.

Ideally, you should run the honeypot listener (```honeypot.py```) on a virtual machine or something similar, then "attack" it with another virtual machine/device, although this depends entirely on your preferences and how committed you are to creating a realistic attack scenario. It is entirely possible to run the script in one terminal and ping the ports from another terminal on the same machine.

## Installation & Setup:

1. Clone the repository and ```cd``` into it. 
2. Pull the required LLM: ```ollama pull llama3.2:3b```
3. Install all the requirements from requirements.txt: ```pip install -r requirements.txt```
4. Run ```python3 honeypot.py```.
5. Open a new terminal window or log into your attacker virtual machine and send a request to one of the ports. For example: ```echo "test" | nc <ip_address_of_server> <port>``` (ports that are currently supported by the honeypot are: 21, 22, 80, 443, 8080, 11434, 4444, and 3389).
6. Navigate to the server's terminal and observe the program has logged the request.
7. Terminate the script by pressing ```ctrl + c``` and look in the directory. You should see a ```honeypot.json``` file.
8. Open the SIEM with: ```streamlit run main.py``` and navigate to the SIEM page. 
9. Upload the JSON log file and observe the data.
10. To use the AI log analyzer, click on the sidebar and navigate to the "LLM Log Analyzer" page. You can now ask the AI questions about the log file that you uploaded.


## Disclaimer:
Despite the precautions taken to protect the LLM from prompt injection via warnings in the system prompt, it is still possible for LLMs to be exploited or hallucinate information. Always double check information given to you by an LLM. 

Be especially cautious if you attempt to use this project in a production environment. Opening yourself up to cyberattacks on purpose can be detrimental to your organization, even with robust security measures. 
