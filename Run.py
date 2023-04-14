from langchain.document_loaders import DirectoryLoader
import os
import sys
from langchain.vectorstores.faiss import FAISS
import logging
import pickle
import platform
from langchain.embeddings import OpenAIEmbeddings
from langchain.text_splitter import CharacterTextSplitter
from pathlib import Path

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

PART = "wiki"
#docs = DirectoryLoader(f"./data/{PART}", glob="**/*.md").load()
ps = list(Path(f"./data/{PART}").glob("**/*.md"))

os_name = platform.system()
clear_command = 'cls' if os_name == 'Windows' else 'clear'

def create_search_index():
    data = []
    sources = []
    for doc in ps:
        with open(doc) as f:
            data.append(f.read())
        sources.append(doc)

    text_splitter = CharacterTextSplitter(chunk_size=1500, separator="\n")
    source_chunks = []
    metadatas = []
    for i, d in enumerate(data):
        splits = text_splitter.split_text(d)
        source_chunks.extend(splits)
        metadatas.extend([{"source": sources[i]}] * len(splits))
    
    search_index = FAISS.from_texts(source_chunks, OpenAIEmbeddings(), metadatas=metadatas) 

    search_index.save_local(f"{PART}.faiss")
    search_index.index = None

    #saving FAISS search index to disk
    with open("search_index.pickle", "wb") as f:
            pickle.dump(search_index, f)
    return "search_index.pickle"

def ask_openai():
    from langchain.chains import VectorDBQAWithSourcesChain,VectorDBQA
    from langchain import OpenAI
    vectorstore = FAISS.load_local(f"{PART}.faiss",embeddings=OpenAIEmbeddings())
    #qa =VectorDBQAWithSourcesChain.from_llm(
    qa =VectorDBQA.from_chain_type(
        llm=OpenAI(
            temperature=0,
            model_name="gpt-3.5-turbo",
            max_tokens=1500
        ),
        vectorstore = vectorstore
    )

    questions = """
    Please read the following HTTP request according to the operation documentation of the nuclei tool:
    ```
    GET /rest/sharelinks/1.0/link?url=https://baidu.com/ HTTP/1.1
    ```

    The HTTP response is as follows:
    ```
    HTTP/1.1 200 OK
    ```
    The above request response is the ssrf vulnerability of the Atlassian Confluence system that is less than version 5.8.6. The author of the discovery is TechbrunchFR, and the cve number is CVE-2021-26072. The vulnerability is the url parameter. Help me generate a nuclei poc, requiring the use of nuclei Use the built-in DNSLOG to judge the vulnerability.API to achieve OOB based vulnerability scanning with automatic Request correlation built in.And add {{BaseURL}} placeholder in front of the path for me.Don't generate too many explanations for me, I only need the complete yaml code.
    
    """
    
    result = qa({"query": questions})
    print(result)

if __name__=='__main__':
    os.environ["OPENAI_API_KEY"] = "sk-xxxxxxxxxxxxxxxxx"
    #construct_index("context_data/src/main/webapp/WEB-INF/views")
    #create_search_index()
    ask_openai()