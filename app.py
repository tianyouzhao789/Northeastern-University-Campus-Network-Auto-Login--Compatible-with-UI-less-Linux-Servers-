"""
东北大学校园网自动登录 - Flask Web服务器
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from neu_login import NEULogin

app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 创建登录实例
login_instance = NEULogin()


@app.route('/')
def index():
    """首页"""
    return render_template('index.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    """登录接口"""
    try:
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({
                'success': False,
                'message': '用户名和密码不能为空'
            })
        
        # 执行登录
        result = login_instance.login(username, password)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'请求处理失败: {str(e)}'
        })


@app.route('/api/logout', methods=['POST'])
def api_logout():
    """下线接口"""
    try:
        result = login_instance.logout()
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'下线请求失败: {str(e)}'
        })


@app.route('/api/status', methods=['GET'])
def api_status():
    """获取网络状态接口"""
    try:
        result = login_instance.get_status()
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'获取状态失败: {str(e)}'
        })


if __name__ == '__main__':
    print("=" * 50)
    print("东北大学校园网自动登录系统")
    print("访问地址: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host='127.0.0.1', port=5000)
