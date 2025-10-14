import streamlit as st
import os
import logging
from langchain_community.document_loaders import UnstructuredPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain.retrievers.multi_query import MultiQueryRetriever
import ollama
import datetime
from auth_oidc import create_nasa_auth
# Alternative implementations available:
# - simple_auth.py: Simple username/password for testing
# - oidc_auth.py: Custom OIDC implementation without authlib


# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants
DOC_PATH = "./data/jpr1700-1ch10-2.pdf"
MODEL_NAME = "mistral"
EMBEDDING_MODEL = "nomic-embed-text"
VECTOR_STORE_NAME = "simple-rag"
PERSIST_DIRECTORY = "./chroma_db"

# NASA Launchpad Credentials
# TODO: Replace these with your actual credentials from NASA Launchpad
NASA_CLIENT_ID = "YOUR_CLIENT_ID_HERE"
NASA_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"


def ingest_pdf(doc_path):
    """Load PDF documents."""
    if os.path.exists(doc_path):
        loader = UnstructuredPDFLoader(file_path=doc_path)
        data = loader.load()
        logging.info("PDF loaded successfully.")
        return data
    else:
        logging.error(f"PDF file not found at path: {doc_path}")
        st.error("PDF file not found.")
        return None


def split_documents(documents):
    """Split documents into smaller chunks."""
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=300)
    chunks = text_splitter.split_documents(documents)
    logging.info("Documents split into chunks.")
    return chunks


@st.cache_resource
def load_vector_db():
    """Load or create the vector database."""
    # Pull the embedding model if not already available.
    ollama.pull(EMBEDDING_MODEL)

    embedding = OllamaEmbeddings(model=EMBEDDING_MODEL)

    if os.path.exists(PERSIST_DIRECTORY):
        vector_db = Chroma(
            embedding_function=embedding,
            collection_name=VECTOR_STORE_NAME,
            persist_directory=PERSIST_DIRECTORY,
        )
        logging.info("Loaded existing vector database.")
    else:
        # Load and process the PDF document
        data = ingest_pdf(DOC_PATH)
        if data is None:
            return None

        # Split the documents into chunks
        chunks = split_documents(data)

        vector_db = Chroma.from_documents(
            documents=chunks,
            embedding=embedding,
            collection_name=VECTOR_STORE_NAME,
            persist_directory=PERSIST_DIRECTORY,
        )
        vector_db.persist()
        logging.info("Vector database created and persisted.")
    return vector_db


def create_retriever(vector_db, llm):
    """Create a multi-query retriever."""
    QUERY_PROMPT = PromptTemplate(
        input_variables=["question"],
        template="""You are an AI language model assisstant.  Your task is to generate five different versions of the given user question to retrieve relevant documents from a vector database. By generating multiple perspectives on the user question, your goal is to help the user overcome some of the limitations of the distance-based similarity search. Provide these alternative questions seperated by newlines.
        Original question: {question}""",
    )

    retriever = MultiQueryRetriever.from_llm(
        vector_db.as_retriever(), llm, prompt=QUERY_PROMPT
    )
    logging.info("Retriever created.")
    return retriever


def create_chain(retriever, llm):
    """Cretae the chain with preserved syntax."""
    # RAG prompt
    template = """Answer the question based ONLY on the following context:
{context}
Question: {question}
"""

    prompt = ChatPromptTemplate.from_template(template)

    chain = (
        {"context": retriever, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )

    logging.info("Chain cretaed with preserved syntax.")
    return chain


def main():
    st.set_page_config(
        page_title="SAGE",
        page_icon="🚀",
    )

    # Require NASA Launchpad OIDC authentication before accessing the app
    auth = create_nasa_auth(NASA_CLIENT_ID, NASA_CLIENT_SECRET)
    auth.require_auth()

    # Show user information and logout button in sidebar
    with st.sidebar:
        st.markdown("### Authentication")
        user_info = auth.get_user_info()
        nasa_info = user_info.get('nasa', {})

        st.success("Authenticated via NASA Launchpad")

        # Display NASA user information
        if nasa_info.get('email'):
            st.info(f"**Email:** {nasa_info['email']}")
        if nasa_info.get('employee_number'):
            st.caption(f"Employee #: {nasa_info['employee_number']}")
        if nasa_info.get('agency_uid'):
            st.caption(f"Agency UID: {nasa_info['agency_uid']}")

        # Show SAGE access status
        if nasa_info.get('has_sage_access'):
            st.success("✓ SAGE Developer Access")
        else:
            st.warning("⚠ No SAGE Developer Role")

        # Show user's SAGE groups
        sage_groups = nasa_info.get('sage_groups', [])
        if sage_groups:
            with st.expander("Groups"):
                for group in sage_groups:
                    st.caption(f"• {group}")

        if st.button("Logout", use_container_width=True):
            auth.logout()
            st.rerun()

    # st.image("./images/NasaControlRoom.jpg", width = 800)  # Image not found, commented out
    st.markdown("<h1 style='text-align: center;'>SAGE<br><span style='font-size: 0.8em;'>Safety Analysis Generation Engine</span></h1>", unsafe_allow_html=True)
    # User input
    user_input = st.text_area(
        "",
        placeholder="Ask me anything about safety analysis documentation...",
        label_visibility="collapsed",
        height=120
    )


    if user_input:
        with st.spinner("Generating response..."):
            try:
                # Initialize the language model
                llm = ChatOllama(model=MODEL_NAME)

                # Load the vector database
                vector_db = load_vector_db()
                if vector_db is None:
                    st.error("Failed to load or create the vector database.")
                    return
                # Create the retriever
                retriever = create_retriever(vector_db, llm)

                # Create the chain
                chain = create_chain(retriever, llm)

                # Get the response
                response = chain.invoke(input=user_input)

                st.markdown("**Assistant:**")
                st.write(response)
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
    else:
        st.info("Please enter a question to get started.", icon="❓")
        
    st.markdown(f"<div style='text-align: center;'><p style='font-family: -apple-system, BlinkMacSystemFont;'>A specialized tool for generating safety analysis documentation<br>Developed by JSC EC4<br>Date: {datetime.date.today()}</p></div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
