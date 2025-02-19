from flask import Flask, request, jsonify
import random

app = Flask(__name__)

brands = ["Dell", "HP", "Lenovo", "Acer", "Asus", "MSI", "Razer", "Apple", "Samsung", "LG"]
cpu_options = ["Intel i3", "Intel i5", "Intel i7", "Intel i9", "AMD Ryzen 3", "AMD Ryzen 5", "AMD Ryzen 7",
               "AMD Ryzen 9"]
gpu_options = ["NVIDIA RTX 3050", "NVIDIA RTX 3060", "NVIDIA RTX 3070", "NVIDIA RTX 3080", "NVIDIA RTX 3090",
               "NVIDIA RTX 4090", "AMD Radeon RX 6600", "AMD Radeon RX 6700", None]
resolutions = ["1366x768", "1920x1080", "2560x1440", "3840x2160"]

# Generate unique laptop specifications
laptops = [
    {"id": i + 1, "brand": random.choice(brands), "name": f"Laptop {i + 1}", "cpu": random.choice(cpu_options),
     "ram": random.choice([4, 8, 16, 32, 64]), "storage": random.choice([128, 256, 512, 1000, 2000]),
     "gpu": random.choice(gpu_options), "monitor_size": random.choice([13.0, 14.0,15.6, 16.0, 17.0, 17.3]),
     "refresh_rate": random.choice([60, 120, 144, 165, 240]), "resolution": random.choice(resolutions)}
    for i in range(50)
]


# Function to check if a laptop meets the requested specs
def meets_specs(laptop, required_specs):
    if required_specs.get('brand') and laptop['brand'].lower() != required_specs['brand'].lower():
        return False
    if required_specs.get('name') and required_specs['name'].lower() not in laptop['name'].lower():
        return False
    if required_specs.get('cpu') and laptop['cpu'].lower() != required_specs['cpu'].lower():
        return False
    if laptop['ram'] < required_specs.get('ram', 0):
        return False
    if laptop['storage'] < required_specs.get('storage', 0):
        return False
    if required_specs.get('gpu') and (
            laptop['gpu'] is None or required_specs['gpu'].lower() not in laptop['gpu'].lower()):
        return False
    if required_specs.get('monitor_size') and laptop['monitor_size'] < required_specs['monitor_size']:
        return False
    if required_specs.get('refresh_rate') and laptop['refresh_rate'] < required_specs['refresh_rate']:
        return False
    if required_specs.get('resolution') and laptop['resolution'] != required_specs['resolution']:
        return False
    return True


@app.route('/get_laptops', methods=['POST'])
def get_laptops():
    data = request.json
    if not data:
        return jsonify({})

    # Filter laptops based on criteria
    filtered_laptops = [laptop for laptop in laptops if meets_specs(laptop, data)]

    # Extract available specs from the filtered laptops
    available_specs = {
        "brands": list(set(l["brand"] for l in filtered_laptops)),
        "cpus": list(set(l["cpu"] for l in filtered_laptops)),
        "rams": sorted(list(set(l["ram"] for l in filtered_laptops))),
        "storages": sorted(list(set(l["storage"] for l in filtered_laptops))),
        "gpus": list(set(l["gpu"] for l in filtered_laptops if l["gpu"])),
        "monitor_sizes": sorted(list(set(l["monitor_size"] for l in filtered_laptops))),
        "refresh_rates": sorted(list(set(l["refresh_rate"] for l in filtered_laptops))),
        "resolutions": list(set(l["resolution"] for l in filtered_laptops))
    }

    return jsonify(available_specs)



@app.route('/get_available_specs', methods=['GET'])
def get_available_specs():
    available_specs = {
        "brands": list(set(laptop['brand'] for laptop in laptops)),
        "cpus": list(set(laptop['cpu'] for laptop in laptops)),
        "rams": sorted(list(set(laptop['ram'] for laptop in laptops))),
        "storages": sorted(list(set(laptop['storage'] for laptop in laptops))),
        "gpus": list(set(laptop['gpu'] for laptop in laptops if laptop['gpu'])),
        "monitor_sizes": sorted(list(set(laptop['monitor_size'] for laptop in laptops))),
        "refresh_rates": sorted(list(set(laptop['refresh_rate'] for laptop in laptops))),
        "resolutions": list(set(laptop['resolution'] for laptop in laptops))
    }

    return jsonify(available_specs or {})  # Ensure an empty dictionary is returned if no data exists


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return jsonify({"error": "Invalid route. Please check the API documentation."}), 404

if __name__ == '__main__':
    app.run(debug=True)
