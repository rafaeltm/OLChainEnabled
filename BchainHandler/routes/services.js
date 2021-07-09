var express = require('express');
var fs = require('fs');
var router = express.Router();

const availableServices =
    [
        {
         "name": "Servicio de impresión",
         "url": "https://www.um.es/web/informatica/",
         "image": "https://www.creativefabrica.com/wp-content/uploads/2019/03/Printer-icon-by-ahlangraphic-1-580x386.jpg",
         "policy": [
             {
                "attributeName": "url:Organization",
                "operation": "REVEAL"
            }
         ]
        },
        {
         "name": "Cita previa",
         "url": "https://www.um.es/web/informatica/",
         "image": "https://cdn.pixabay.com/photo/2019/01/01/14/55/calendar-3906791_1280.jpg",
         "policy": [
            {
                "attributeName": "url:Mail",
                "operation": "REVEAL"
            }
         ]
        },
        {
         "name": "Actas",
         "url": "https://www.um.es/web/informatica/",
         "image": "https://c0.klipartz.com/pngpicture/860/53/gratis-png-agenda-de-iconos-de-la-computadora-convenciones-actas-de-la-reunion-herramienta-de-programacion-de-reuniones.png",
         "policy": [
            {
                "attributeName": "url:Role",
                "operation": "REVEAL"
            }
         ],
        },
        {
         "name": "Reserva sala de estudio",
         "url": "https://www.um.es/web/informatica/",
         "image": "https://www.creativefabrica.com/wp-content/uploads/2018/11/Reading-book-logo-by-hartgraphic-580x386.jpg",
         "policy": [
            {
                "attributeName": "url:Organization",
                "operation": "REVEAL"
            },
            {
                "attributeName": "url:Role",
                "operation": "REVEAL"
            }
         ]
        },
        {
            "name": "Servicio de becas",
            "url": "https://www.um.es/web/informatica/",
            "image": "https://www.iesjacaranda.es/web/media/k2/items/cache/3f4808b525a42a0bb340252b3c0de1d3_M.jpg",
            "policy": [
               {
                   "attributeName": "url:Organization",
                   "operation": "REVEAL"
               },
               {
                   "attributeName": "url:DateOfBirth",
                   "operation": "LESSTHAN",
                   "value": {
                       "attr": 947030400000,
                       "type": "DATE"
                   }
               },
               {
                    "attributeName": "url:AnnualSalary",
                    "operation": "INRANGE",
                    "value": {
                        "attr": 0,
                        "type": "INTEGER"
                    },
                    "extra": {
                        "attr": 40000,
                        "type": "INTEGER"
                    }
                }
            ]
           }
     ];

router.get('/', function(req, res, next) {
    res.status(200).send(availableServices);
});
  

module.exports = router;
