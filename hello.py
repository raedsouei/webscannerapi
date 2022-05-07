from scanner import *
from flask import Flask ,request , jsonify

app = Flask(__name__)

@app.route('/api',methods=['GET'])
def hello():
    req = str(request.args['req'])
    print(req)
    scan = VulnerabilityScanner(req)
    result = scan.Run()
    
    res = {}
    res['target links'] = result[0]
    res['vurnuble links'] = result[1]
    keys = list(result[2].keys())
    res['link for vurnuble forms'] = keys
   
    
    values = list(result[2].values())
    v = []
    for elt in values:
        elt = str(elt).replace("<",'&#60;')
        elt = str(elt).replace(">",'&gt;')
        v.append(elt)
    
    
    
    res['vurnuble forms'] = v
    
    
    return res
