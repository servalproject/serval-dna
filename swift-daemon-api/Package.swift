import PackageDescription

let package = Package(
        name: "ServalDNA"
    )

products.append(
        Product(name: "ServalDNA", type: .Library(.Static), modules: "ServalDNA")
    )
