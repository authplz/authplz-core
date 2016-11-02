
module.exports = [
    {
        test: /\.jsx?$/,
        exclude: /(node_modules|bower_components|public|static)/,
        loader: "babel"
    },
    { 
        test: /\.css$/, 
        loader: "style-loader!css-loader" 
    },
    {
        test: /\.eot(\?v=\d+\.\d+\.\d+)?$/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "file"
    },
    {
        test: /\.(woff|woff2)$/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url?prefix=font/&limit=5000"
    },
    {
        test: /\.ttf(\?v=\d+\.\d+\.\d+)?$/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url?limit=10000&mimetype=application/octet-stream"
    },
    {
        test: /\.svg(\?v=\d+\.\d+\.\d+)?$/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url?limit=10000&mimetype=image/svg+xml"
    },
    {
        test: /\.gif/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url-loader?limit=10000&mimetype=image/gif"
    },
    {
        test: /\.jpg/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url-loader?limit=10000&mimetype=image/jpg"
    },
    {
        test: /\.png/,
        exclude: /(node_modules|bower_components|static)/,
        loader: "url-loader?limit=10000&mimetype=image/png"
    },
    { 
        test: /bootstrap\/.+\.(jsx|js)$/,
        loader: 'imports?jQuery=jquery,$=jquery,this=>window'
    }
];
