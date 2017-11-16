$(document).ready(function() {
    $('#packages').DataTable( {
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
