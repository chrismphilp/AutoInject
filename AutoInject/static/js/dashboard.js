$(document).ready(function() {
    $('#packages').DataTable( {
        "lengthMenu": [ 10, 25 ],
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
    // // var JSON_data = {{ package_JSON_data }};

    table.row.add( [
        "Hello",
        "Hola",
        "Senor"
    ] ).draw();

} );
