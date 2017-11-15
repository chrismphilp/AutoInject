$(document).ready(function() {
    $('#packages').DataTable( {
        "paging":   true,
        "ordering": true,
        "order": [[ 1, "desc" ]],
        "info":     true
    } );
} );
