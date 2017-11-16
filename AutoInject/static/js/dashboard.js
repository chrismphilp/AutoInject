$(document).ready(function() {
    $('#packages').DataTable( {
        "paging":       true,
        "ordering":     true,
        "order":        [[ 1, "desc" ]],
        "info":         true,
        "columns": [
            { data: "package_name" },
            { data: "package_version" },
            { data: "architecture" }
        ]  
    } );

    var table = $('#packages').DataTable();
    // var JSON_data = {{ package_JSON_data }};

    table.row.add( [
        data.package_name,
        data.version,
        data.architecture
    ] ).draw( false );

} );
