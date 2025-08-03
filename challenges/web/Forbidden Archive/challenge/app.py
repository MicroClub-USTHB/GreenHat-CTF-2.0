from flask import Flask, request, render_template, Response
from lxml import etree

app = Flask(__name__)

# Sample product data
products = {
    "1": {"name": "Black Data Archive", "price": "$1k", "description": "Contains classified military intelligence and strategic operations data from 2015-2023. Access requires Omega clearance."},
    "2": {"name": "Red Data Archiv", "price": "$5k", "description": "Stored diplomatic cables and international treaty negotiations. Includes extraterrestrial research materials. Eyes only."},
    "3": {"name": "Gold Data Archive", "price": "10k", "description": "Archived psychic warfare experiments and chronal displacement research. Quantum encryption required for full access."}
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api', methods=['POST'])
def api():
    content_type = request.headers.get('Content-Type')
    if 'xml' not in content_type.lower():
        return Response("Invalid content type", status=400)
    
    try:
        # Intentionally using vulnerable XML parser that processes external entities
        xml_data = request.data
        
        # Create parser that resolves external entities (vulnerable)
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(xml_data, parser)
        
        # Find product ID in XML
        product_id = root.find('id').text
        
        # Check if it's a valid product ID
        if product_id in products:
            product = products[product_id]
            response_xml = f"""<product>
                <name>{product['name']}</name>
                <price>{product['price']}</price>
                <description>{product['description']}</description>
            </product>"""
            return Response(response_xml, mimetype='application/xml')
        else:
            # This is where the XXE vulnerability exists
            # The parser will process any entities in the invalid ID
            return Response(f"<error>Invalid product ID: {product_id}</error>", mimetype='application/xml')
            
    except Exception as e:
        return Response(f"<error>Error processing request: {str(e)}</error>", mimetype='application/xml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)