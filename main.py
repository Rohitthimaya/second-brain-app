from flask import Flask, request, jsonify
from sentence_transformers import SentenceTransformer

app = Flask(__name__)
# model = SentenceTransformer('all-MiniLM-L6-v2')  # Or any other ST model
model = SentenceTransformer("BAAI/bge-large-en-v1.5") # 1536 dimensions
print("Model embedding dimension:", model.get_sentence_embedding_dimension())  # Should print 1536


@app.route('/embed', methods=['POST'])
def embed():
    data = request.json
    texts = data.get("texts", [])
    embeddings = model.encode(texts, convert_to_numpy=True).tolist()
    return jsonify({"embeddings": embeddings})

if __name__ == '__main__':
    app.run(port=5000)

