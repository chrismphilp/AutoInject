$(document).ready(function() {
    $('#packages').DataTable( {
        "columnDefs": [
            { "name": "engine",   "targets": 0 },
            { "name": "browser",  "targets": 1 },
            { "name": "platform", "targets": 2 },
            { "name": "version",  "targets": 3 },
            { "name": "grade",    "targets": 4 }
        ],
        "lengthMenu":   [ 10, 25 ],
        "paging":       true,
        "processing":   true,
        "ordering":     true,
        "order":        [[ 1, "desc" ]],
        "info":         true
    } );

    var table = $('#packages').DataTable();
    // // var JSON_data = {{ package_JSON_data }};

    table.row.add( [
        "Hello",
        "Hola",
        "Senor"
    ] ).draw();

} );
