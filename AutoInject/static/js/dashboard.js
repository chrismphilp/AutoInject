$(document).ready(function() {
    $('#packages').DataTable( {
        "lengthMenu":   [ 10, 15 ],
        "paging":       true,
        "processing":   true,
        "ordering":     true,
        "order":        [[ 0, "asc" ]],
        "info":         true
    } );
} );
