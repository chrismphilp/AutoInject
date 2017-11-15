$(document).ready(function() {
    $('#packages').DataTable( {
        "paging":   true,
        "ordering": true,
        "order": [[ 1, "desc" ]],
        "info":     true,
        "columns": [
            { data: "package_name" },
            { data: "package_version" },
            { data: "architecture" }
        ]  
    } );
} );
