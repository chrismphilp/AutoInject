$(document).ready(function() {
    $('#packages').DataTable( {
        "paging":   true,
        "ordering": true,
        "order": [[ 1, "desc" ]],
        "info":     true
    } );
} );

var table = $('#packages').DataTable();

table.row.add( {
       "Tiger Nixon",
       "System Architect",
       "$3,120",
} ).draw();