import os, sys; current_dir = os.path.dirname(os.path.abspath(__file__)); sys.path.append(os.path.join(current_dir, 'server')); from app import app, db;
if __name__ == "__main__": 
    print("Server running on http://127.0.0.1:5000"); 
    with app.app_context(): db.create_all(); 
    app.run(debug=True, port=5000)