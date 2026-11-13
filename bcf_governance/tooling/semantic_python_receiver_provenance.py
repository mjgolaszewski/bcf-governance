"""Associate normalization with a source-produced record, never annotation purity."""
from __future__ import annotations

from typing import Any


def resolve_normalization_receivers(inventory: dict[str, Any]) -> None:
    functions={str(row['symbol']):row for row in inventory.get('functions',[])}
    classes={str(row['symbol']):row for row in inventory.get('classes',[])}
    for function in functions.values():
        by_site: dict[str,list[tuple[int,dict[str,Any]]]]={}
        for index,call in enumerate(function.get('calls',[])):
            if not call.get('implicit_callback'):
                by_site.setdefault(f"call:{call.get('line')}:{call.get('column')}",[]).append((index,call))
        for normalization in function.get('normalizations',[]):
            sources=normalization.get('receiver_result_sources',[])
            subjects=set()
            qualified=bool(sources)
            for source in sources:
                calls=by_site.get(source,[])
                if len(calls)!=1:
                    qualified=False
                    break
                index,call=calls[0]
                target=str(call.get('called_symbol',''))
                candidates={target} if target in classes else set()
                producer=functions.get(target,{})
                if producer.get('direct_class_receiver_return'):
                    candidates.update(str(binding['constructed_symbol'])
                        for inner in producer.get('calls',[])
                        for binding in inner.get('class_constructor_bindings',[])
                        if binding.get('binding_caller')==function['symbol']
                        and binding.get('binding_occurrence')==index)
                if len(candidates)!=1:
                    qualified=False
                    break
                subject=next(iter(candidates))
                record=classes.get(subject,{})
                if (not record.get('closed_class_binding') or record.get('library_model_binding')
                        or record.get('dataclass_default_factories')
                        or any(method['name'] in {'__init__','__new__','__post_init__','__getattr__','__getattribute__'}
                               for method in record.get('methods',[]))):
                    qualified=False
                    break
                subjects.add(subject)
            if qualified:
                normalization['source_receiver_subjects']=sorted(subjects)
                normalization['receiver_subject_binding']='closed_source_constructor_result'
