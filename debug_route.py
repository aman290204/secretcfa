# Quick debug route to check data folder
@app.route('/debug/check-files')
def debug_check_files():
    """Debug route to check if files are accessible"""
    import os
    import json
    
    info = {
        'BASE_DIR': BASE_DIR,
        'DATA_FOLDER': DATA_FOLDER,
        'data_folder_exists': os.path.exists(DATA_FOLDER),
        'data_folder_contents': [],
        'possible_data_paths': []
    }
    
    # Check if data folder exists
    if os.path.exists(DATA_FOLDER):
        try:
            info['data_folder_contents'] = os.listdir(DATA_FOLDER)[:10]  # First 10 files
        except Exception as e:
            info['error_listing'] = str(e)
    
    # Check alternative paths
    for name in ['data', 'Data', 'DATA']:
        path = os.path.join(BASE_DIR, name)
        info['possible_data_paths'].append({
            'path': path,
            'exists': os.path.exists(path),
            'files_count': len(os.listdir(path)) if os.path.exists(path) else 0
        })
    
    return jsonify(info)
